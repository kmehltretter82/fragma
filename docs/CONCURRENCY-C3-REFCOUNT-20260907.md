# C3 System V IPC refcount lifetime pilot — 2026-09-07

Status: accepted for one narrow production lifetime decision with eight
configured SMP implementation mappings; C3 remains incomplete.

The current standalone evidence is
[`results/concurrency-c3-ipc-refcount-20260907-06`](../results/concurrency-c3-ipc-refcount-20260907-06/SUMMARY.md).
It passes all 739 gates, accepts one source-linked kernel property, and accepts
eight implementation mappings for that same property. It found no new Linux
defect: the selected IPC code uses the refcount API correctly.

The preceding `-01` run passed the same model, source, build and outcome gates.
Run `-02` renews the receipt after changing the property wording from a generic
“report” to the precise observable actions: schedule destruction and return a
successful get. Run `-03` retains that property and A/B outcome while adding
arm64, riscv64 and s390x source, compiler, object, symbol and disassembly gates.
It also uses target `objdump --disassemble=<function>` independently for each
function, so RISC-V local labels cannot truncate the inspected function body.
Run `-04` is retained as a failed evidence-matcher attempt: 736/738 checks
passed, but two PowerPC instruction-order tokens assumed tab-separated operands
where GNU objdump emits aligned spaces. No model, source, compiler, object or
kernel behavior failed. Run `-05` fixes only those match strings and reruns the
whole gate into a fresh directory.
Run `-05` then passed 738/738 mechanical gates, but final human readback found
that an exclusion sentence still named only the old four-profile set. Run `-06`
updates that sentence, adds an exact scope-binding gate and negative unit test,
and reruns all model, source and build work. Thus `-05` is superseded despite
its green computed result.

## Accepted property

The pinned `ipc/util.h` contract says that its reference-counted objects start
at one, that a put reducing the count to zero schedules RCU destruction, and
that the caller must guarantee locking. Under that prerequisite, select exactly
one `ipc_rcu_putref()` and one concurrent `ipc_rcu_getref()` operating on the
same initially-one `kern_ipc_perm::refcount`, with no third update.

The two operations cannot both:

- make the final-put decision and schedule `call_rcu()`; and
- return a successful get from `refcount_inc_not_zero()`.

There are only two valid linearizations. If the get wins, it changes 1 to 2 and
the put observes 2, leaving 1 without scheduling destruction. If the put wins,
it changes 1 to 0 and the get cannot increment zero. The property assumes the
caller's lock/RCU discipline keeps `ptr` and its refcount storage valid while
the get is attempted. It does not prove that prerequisite.

## Functional A/B model

Both LKMM cases ask for the identical bad condition:

```text
exists (0:released=1 /\ 1:acquired=1)
```

| Case | Get operation | Distinct states | Bad/good witnesses | Result |
| --- | --- | ---: | ---: | --- |
| Source abstraction | relaxed compare/exchange 1 to 2 | 2 | 0/2 | `Never` |
| Unsafe control | unconditional relaxed increment | 2 | 1/1 | `Sometimes` |

The negative remains permanently ineligible for verification acceptance. Its
bad witness is the deliberate resurrection sequence: the put changes 1 to 0
and decides to destroy, then the unconditional increment changes 0 back to 1.
This demonstrates that the query detects the lifetime failure excluded by the
real get-unless-zero operation.

`refcount_inc_not_zero()` begins with `refcount_read()` and retries
`atomic_try_cmpxchg_relaxed()`. LKMM does not directly spell the try-CAS helper,
so the positive uses `atomic_cmpxchg_relaxed(refs, 1, 2)`. That is exact for this
bounded outcome: there is one initial reference and only one competing
decrement. If the first CAS succeeds, the get wins. If it fails, the decrement
has already installed zero; the source loop reads that zero and stops rather
than retrying. Saturation and any other count are outside the property.

The put side retains the source implementation's
`atomic_fetch_sub_release(1, refs)` and records `released=1` only when the old
value is one. The successful source path also executes
`smp_acquire__after_ctrl_dep()`. That ordering matters for later destruction
work but cannot change this same-refcount mutual-success question; no
cross-object ordering claim is inferred from its omission.

## Source and configured implementation gates

The source gate pins and rechecks:

- `ipc/util.c`'s one-line get and its final-put test before `call_rcu()`;
- `ipc/util.h`'s initial-count, destruction and caller-locking contract;
- the full `refcount_inc_not_zero()` chain through its zero test and relaxed
  try-CAS loop;
- the full `refcount_dec_and_test()` chain through release fetch-sub, exact
  1-to-0 test and acquire-after-control operation;
- the kernel refcount ordering documentation;
- the instrumented atomic API, generic fallback, LKMM RMW atomicity axiom, and
  x86-64, arm64, RISC-V, s390, ARM32, PowerPC32, SuperH and Alpha
  atomic/cmpxchg/barrier implementation files;
- the System V IPC Kconfig/Makefile selection and actual configured objects.

Eight dedicated SMP builds compile the real `ipc/util.o`, not a project wrapper.
All use GCC 15.2.0 and GNU binutils 2.46 already present on the machine.

| Profile | ELF | Config SHA-256 | Object SHA-256 | Checked lowering |
| --- | --- | --- | --- | --- |
| x86-64 | 64-bit LE, machine 62 | `c1d909f833602f5d8fb7fba52322c1f411c44fe4e41a44b52ac5d897e3f3033e` | `00b7dfa8b08c8d76546e13cc8adb5e5102480225c444902ea46aa6c993525d6d` | get `lock cmpxchg`; put `lock xadd` |
| arm64 | 64-bit LE, machine 183 | `d28c867e07d4ade1ce14ea23b0b45707fde9459c526d492e0cdec042bcbf0219` | `1bda4df1720f4a58034f1163ee31ff19d36dea2307435c75e7c6518e4688a7d9` | get LSE `cas` and LL/SC `ldxr`/`stxr`; put LSE `ldaddl` and LL/SC `ldxr`/`stlxr`, then `dmb ishld` |
| riscv64 | 64-bit LE, machine 243 | `fe92d0e05bc9be603ec62108f63b02ac7fbf2e20f08789903525fdea8f58f19b` | `54b28e7a322a688cd1a196b153a037c92db1f317dbdb50c4268856f41944c92d` | get Zacas `amocas.w` and `lr.w`/`sc.w`; put release fence, `amoadd.w`, then successful-path read fence |
| s390x | 64-bit BE, machine 22 | `a7676e53663ef8a496f2da61cd36b0ef67e62420d3fa50d233aa146cef155d01` | `b92d6cb9350e9b4fefa88b75b7a69a83ad7d7231106813e89d8e6f8b704346d3` | get `cs`; put `laa` |
| ARMv7 | 32-bit LE, machine 40 | `9001027fc1668165f240e4012d7a0505953839ac85c128d15ab8e39daaf0b412` | `17f07ba07cdcdaafe3eb4c9f65c872acf3bba7cc697acc8df7dec419059e4b20` | get and put `ldrex`/`strex`; put `dmb ish` |
| PowerPC32 CHRP | 32-bit BE, machine 20 | `2ce33c1da81f6882148455cd62c55ecb5a7f8ebe83a11b0ba452ed3cc50ec1e7` | `68021ae57fdbf7ce71efe35877ca5d98fdd09fe7160e7f0e1486bd82a469fad3` | get and put `lwarx`/`stwcx.`; put `hwsync` |
| SuperH SH-X3 | 32-bit LE, machine 42 | `e53d91d1ed9b63b39c7abf0a3c9711c88c0ef0ffb30d17309720098cd9538047` | `b1fef80ad64b4fdd77542c261c027a05d260b90d92ff53b8454665f8a8084791` | get and put `movli.l`/`movco.l`; `synco` |
| Alpha generic SMP | 64-bit LE, machine 36902 | `21d6b92b20bfb82d67380adc6624e767aeacd54be1bec0950e3ccca309816902` | `cb63e40524cedb288279cb14d469a7a851046dead44dda22d45be8066c8986b5` | get and put `ldl_l`/`stl_c`; `mb` |

Every profile pins both global function symbols and the `call_rcu` relocation.
The arm64 and RISC-V objects contain runtime-selected alternative atomic paths;
the gate requires both visible paths rather than pretending the object contains
only one. The builds run sequentially so their make jobservers and output trees
cannot interfere. Raw commands, stdout/stderr, model results, source/model facts,
identities and artifact hashes are retained in the local evidence directory.
The runner now classifies build warnings, errors, jobserver messages and
`File exists` contamination. Every unlisted diagnostic fails the profile. The
only declared exception is SuperH's exact cold-build `checksyscalls.sh` warning
that `clone3` is not implemented; the accepted `-06` run observed no diagnostic.
Alpha starts from `defconfig`, applies the recorded `scripts/config --enable SMP`
mutation, finalizes with `olddefconfig`, and checks the resulting config hash.

## Boundaries and next work

Not accepted: an unstabilized or already reclaimed pointer, callback execution,
RCU grace periods, allocator reuse, ABA, `SLAB_TYPESAFE_BY_RCU`, arbitrary
initial counts, a third update, saturation/overflow/underflow, warning paths,
whole-IPC or whole-RCU correctness, whole-kernel race freedom, or any progress,
fairness, retry-bound, lock-free or wait-free guarantee.

The implementation mapping is limited to x86-64, arm64, riscv64, s390x, ARM32,
PowerPC32, SuperH and Alpha, all under the exact SMP configurations above. The
architecture-independent refcount contract and LKMM result do not activate any
other architecture without its source/macro/compiler/object evidence. C3 still
needs any separately justified progress property, mappings for the remaining
Linux architectures and broader lockless protocol coverage. C4 remains
responsible for explicit RCU grace-period and reclamation reasoning.

The available m68k `virt_defconfig` is UP-only, so its successful exploratory
`ipc/util.o` build is not promoted into this two-CPU SMP mapping. It can support
a separately worded local task/interrupt claim or a non-concurrency compiler
mapping, but not this profile's `smp-multicpu` label.

The post-expansion project regression run passes
[986 tests](../results/tests-concurrency-c3-eight-arch-refcount-20260907.log),
with 20 pre-existing conditional skips.

Reproduce with:

```text
python3 -m fragma concurrency-c3-ipc-refcount \
  --output results/concurrency-c3-ipc-refcount-NEW --timeout 180
```

This performs static model checking and an out-of-tree object build. It does
not execute code in the running kernel, load a module, install a package or use
`sudo`.

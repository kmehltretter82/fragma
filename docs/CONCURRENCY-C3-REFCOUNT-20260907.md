# C3 System V IPC refcount lifetime and bounded-progress pilot — 2026-09-07

Status: accepted for one narrow production lifetime decision with nine
configured SMP implementation mappings and one separate bounded progress
property with three single-instruction-CAS implementation mappings; C3 remains
incomplete.

The current standalone evidence is
[`results/concurrency-c3-ipc-refcount-20260907-09`](../results/concurrency-c3-ipc-refcount-20260907-09/SUMMARY.md).
It passes all 848 gates, accepts two separately bounded source-linked kernel
properties, and accepts nine lifetime plus three progress implementation mappings.
The receipt pins 77 input identities and retains 331 raw artifacts. It found no
new Linux defect: the selected IPC code uses the refcount API correctly.

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
its green computed result. Run `-07` retains the same property and A/B outcome,
then adds a fresh `ARCH=um`, `SUBARCH=x86_64`, `CONFIG_SMP=y` mapping with
explicit UML configuration, x86-header routing, symbol and disassembly gates.
Run `-08` retains the lifetime result and all nine mappings, then adds the
separate finite-state progress property, three detecting controls and exact
native/UML x86-64 retry-loop mappings.
Run `-09` adds s390 only after checking its strong try-CAS source macro, in/out
comparison operand, real `CS` instruction and mismatch retry branch.

## Accepted lifetime property

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

## Accepted bounded progress property

The progress claim is separate from the lifetime model. For the selected native
x86-64, s390x and UML x86-64 `ipc_rcu_getref()` implementations, assume that:

- the caller keeps the object and refcount storage valid;
- the operation is scheduled for every modeled loop step and once after
  interference quiesces;
- `atomic_try_cmpxchg_relaxed()` is strong and non-spurious, and updates its
  expected argument with the current counter after a mismatch; and
- there are at most three interfering counter observations in the explicit
  zero-through-three domain, with saturation and overflow unreachable.

The project-owned finite-state enumerator checks all 340 initial-value and
interference-prefix combinations. Every source-candidate schedule returns by
zero exit or successful increment in at most four CAS attempts; 150 schedules
succeed and 190 exit at zero. A maximum witness observes `2, 1, 2`, fails three
CAS attempts as the expected value is refreshed, then succeeds after quiescence
on attempt four.

Three permanently ineligible controls make the boundary observable. Retaining a
stale expected value leaves 117 of 340 schedules in a quiescent retry cycle;
allowing spurious failure creates a one-state cycle; and alternating unbounded
interference between one and two creates a two-state starvation cycle. Thus the
accepted result is a finite-quiescence termination bound, not wait-freedom,
general lock-free progress, scheduler fairness or global CPU forward progress.

Both selected x86 objects lower the operation to a locked `CMPXCHG`, update the
expected register from `EAX` on mismatch and branch back to the source retry.
The s390 object lowers the 32-bit operation to one `CS`; its in/out comparison
operand receives the observed word on mismatch before the condition-code branch
returns to the zero check. All three exact objects and disassemblies are checked
by the same build gate. The other six lifetime profiles use
architecture-dependent operations, including LL/SC loops; this pilot does not
establish their machine-level progress.

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
  atomic/cmpxchg/barrier implementation files, plus UML's SMP Kconfig,
  `SUBARCH`-to-x86 header route and UML x86 barrier implementation;
- the System V IPC Kconfig/Makefile selection and actual configured objects.

Nine dedicated SMP builds compile the real `ipc/util.o`, not a project wrapper.
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
| UML x86-64 SMP | 64-bit LE, machine 62 | `d1152890f190eca30f4d27785da89871dd2d95c2378ed5b479114aa29e8ca2d1` | `fdecff20215771537646f5604c476691260b94d44d70020ff350220de2a34c31` | explicit x86 header route; get `lock cmpxchg`; put `lock xadd`, then `lfence` |

Every profile pins both global function symbols and the `call_rcu` relocation.
The arm64 and RISC-V objects contain runtime-selected alternative atomic paths;
the gate requires both visible paths rather than pretending the object contains
only one. The builds run sequentially so their make jobservers and output trees
cannot interfere. Raw commands, stdout/stderr, model results, source/model facts,
identities and artifact hashes are retained in the local evidence directory.
The runner now classifies build warnings, errors, jobserver messages and
`File exists` contamination. Every unlisted diagnostic fails the profile. The
only declared exception is SuperH's exact cold-build `checksyscalls.sh` warning
that `clone3` is not implemented; the accepted `-07` run observed no diagnostic.
Alpha starts from `defconfig`, applies the recorded `scripts/config --enable SMP`
mutation, finalizes with `olddefconfig`, and checks the resulting config hash.
UML independently starts from `x86_64_defconfig`, records the same explicit SMP
mutation, finalizes it under both `ARCH=um` and `SUBARCH=x86_64`, and checks
UML-specific flags rather than inheriting the native x86 object.

## Boundaries and next work

Not accepted: an unstabilized or already reclaimed pointer, callback execution,
RCU grace periods, allocator reuse, ABA, `SLAB_TYPESAFE_BY_RCU`, arbitrary
initial counts, a third update, saturation/overflow/underflow, warning paths,
whole-IPC or whole-RCU correctness, or whole-kernel race freedom. The lifetime
model itself accepts no progress result. The separate finite-state property
accepts only its stated three-observation/four-attempt quiescent bound; it does
not accept unbounded progress, scheduler fairness, wait-freedom, general
lock-freedom or LL/SC implementation liveness.

The implementation mapping is limited to x86-64, arm64, riscv64, s390x, ARM32,
PowerPC32, SuperH, Alpha and UML x86-64, all under the exact SMP configurations
above. The architecture-independent refcount contract and LKMM result do not
activate any other architecture without its source/macro/compiler/object
evidence. The progress implementation mapping is narrower still: native/UML
x86-64 and s390x only. C3 still needs unbounded/LL/SC progress evaluation, mappings for the
remaining Linux architectures and broader lockless protocol coverage. C4 remains
responsible for explicit RCU grace-period and reclamation reasoning.

The available m68k `virt_defconfig` is UP-only, so its successful exploratory
`ipc/util.o` build is not promoted into this two-CPU SMP mapping. It can support
a separately worded local task/interrupt claim or a non-concurrency compiler
mapping, but not this profile's `smp-multicpu` label.

The post-expansion project regression run passes
[990 tests](../results/tests-concurrency-c3-s390-progress-20260907.log),
with 20 pre-existing conditional skips; all 22 focused IPC/refcount tests pass.

Reproduce with:

```text
python3 -m fragma concurrency-c3-ipc-refcount \
  --output results/concurrency-c3-ipc-refcount-NEW --timeout 180
```

This performs static model checking and an out-of-tree object build. It does
not execute code in the running kernel, load a module, install a package or use
`sudo`.

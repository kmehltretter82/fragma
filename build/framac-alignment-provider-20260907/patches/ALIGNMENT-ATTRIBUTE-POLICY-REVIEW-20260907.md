# Explicit alignment-attribute policy proposal — 2026-09-07

Private source proposal only. Nothing was applied to `baseline-1`, the installed
toolchain, production modules/configuration, or old evidence. No compiler,
analyzer, build, generator, or native program was executed.

Patch: [0002-alignment-attribute-policy.patch](0002-alignment-attribute-policy.patch)
SHA-256 `bc59c22b6fc18a9a4e0ab8406e7e0332e5a53091029de6e611314ad2079fec9b`. Exactly six source files, twelve hunks,
79 added lines and one removed line. All old/new hunk counts, coordinates and
exact context bytes were checked by applying the patch in memory against the
unmodified private Frama-C 33.0 source. The proposed Python generator was parsed
with Python's AST parser only. OCaml/PPX compilation and runtime controls remain
pending.

## Interface and failure boundary

`Machdep.mach.alignment_attribute_policy : string` defaults to `"legacy"`
when omitted from YAML. The only opt-in value is `"clang-21-u32-bits"`.
`Machine.clang_u32_alignment_policy : unit -> bool` returns true only for
that valid explicit selection.

The schema restricts values through an enum. The normal `mach_of_yaml`
decoder preserves its existing type/default checks, rejects duplicate policy
keys, then validates the policy and prerequisites. Unknown values, a compiler
other than literal `"clang"`, or a maximum other than 4294967296 bytes fail
closed. `Machine.init` also validates direct OCaml record inputs before
changing machine state; the getter repeats validation. The maximum is compared
with Zarith's exact 2^32, not a host-sized OCaml integer literal or a lowered
ceiling. Legacy policy imposes no new compiler/maximum restriction.

The only explicit built-in record constructor found is `Machdep.dummy`; it
gets legacy. Existing predefined models are YAML and need no edits. The pretty
printer includes the new policy, so machine identity remains inspectable.
No CIL, Cabs, source attribute, requested alignment, or effective-contribution
calculation changes in this patch.

The authorized sixth-file correction changes only JSON Schema's required-field
list: exactly `optional: true` fields are excluded. Existing generation already
omits unset optional fields (`make_machdep.py:468–471`), while its old schema
checker incorrectly required every schema key (`:115–118`). All genuinely
required fields and `additionalProperties: false` remain. No generator body,
compiler invocation, output mode, or installed generator changes.

## Source rationale and cache state

Retained exact upstream LLVM 21.1.8:
`SemaDeclAttr.cpp:4614–4665` checks the original byte request, then caches
`static_cast<unsigned>(AlignVal * Context.getCharWidth())`;
`AttrImpl.cpp:250–276` uses the present unsigned cache, including zero.
Hashes were rechecked:
`SemaDeclAttr.cpp=69cca601086aa427124035c4e2b657da2c8c084e99228f8ad74dc54c7bf9a2ea`,
`AttrImpl.cpp=989be0cac834dab752add759a355c65d0fb9f81d8633693b7458643a3336d191`.
See [source provenance](../../clang-21-alignment-source-20260907/README.md);
these upstream files do not authenticate Ubuntu's full compiler build.

Frama-C already assumes eight-bit bytes (`machdep.ml:590–594`); there is no
independent character-width machdep field. The unsigned cache belongs to the
compiler implementation, not the analyzed target, so target `sizeof(int)`
is deliberately not used to infer its 32-bit width. No endian, pointer-width,
or architecture-name restriction is fabricated.

The policy lives in the existing projectified machine record, not a new global
reference. Existing dependencies are
`Kernel.Machdep.self -> Machine.self -> Ast.self -> Cil.selfTypSize`
(`machine.ml:276`, `ast.ml:20,76–78`). This covers ordinary parameter/project
invalidation; it is not automatic detection of external edits to the same YAML
pathname. Fresh hash-bound invocations remain necessary.

## Required later controls — not executed

- Load existing predefined YAMLs and explicit legacy YAMLs unchanged; the
  getter must remain false. Run existing-YAML `--check-only` regressions,
  including omitted optional GNU-alignment fields and the omitted new field.
  Removing a genuinely required field must still reject.
- Valid explicit Clang/2^32 opt-in must load and return true. Unknown/empty/
  wrong-case/non-string policy values, duplicate policy keys, compiler paths
  or GCC instead of literal clang, and changed/missing/non-integer maxima must
  reject through their intended loader/schema diagnostics.
- Direct OCaml record inputs must receive the same compatibility validation.
  Project changes between legacy and opt-in must invalidate cached layouts.
- The later consumer patch must preserve source requests and validate each
  spelling/context before computing or combining effective contributions.
  This declaration patch alone cannot repair any alignment result.
- Build/PPX/interface checks, complete 55-case context calibration, max_align_t
  controls and genuine-kernel model gates remain mandatory. No Hexagon
  registration, profile promotion, L1 acceptance, or kernel-bug claim follows.

## Exact source identities

Paths are relative to the pinned
`baseline-1/source/frama-c-33.0-Arsenic` tree. Proposed hashes refer only to
the in-memory patched bytes, not files placed in that tree.

```text
src/kernel_internals/runtime/machdep.ml
  base:     d3dc80c72d4d0d0a69a268bac387ecd81aa9b5f01e5a31c730aeebc799c1b42d
  proposed: 48eee9c062366d85c69acbf5667b4279ec354ad00bcdd43fab283b09f3fedf19
src/kernel_internals/runtime/machdep.mli
  base:     5dcaff73ecbc3e2aeeea3ef6f5267bf95edb9dfb8e1527ab93cd313f81fdd1ba
  proposed: dc88a6c3fbd3c79e1d9afafe150fac5bd5bba4360af3f735971f590cb65433d6
src/kernel_services/ast_data/machine.ml
  base:     5203f0a7ac575e44f4eb7bdd4d979d912d74ff680571591d362ff63278f81850
  proposed: ab2fd88277c5615b9e0510eedb686a84618aa2c43de23fba9baed5036af63456
src/kernel_services/ast_data/machine.mli
  base:     f69a275c1050d1a18b5d1dd1dc41b706119daf25c1ac1083273ef7597b2338c2
  proposed: c4be0748b6e5451f8a1cf6e4fdaf4b3e882fc2c5ae30a122f2706e75bf74df26
share/machdeps/machdep-schema.yaml
  base:     ce8de93d93cc3bfbd8ad843bd6b44dd3f89ac5bd981f48b93433006b1fa34400
  proposed: 5947d5d49770804f64edee38d3cba2a7e1ecaa6e9b05ffc5cfdda6f6ad78d7ef
share/machdeps/make_machdep/make_machdep.py
  base:     889d3ca26ea964aebcc2e9a1c2fe5ccab3f064b29fd8c69f7c90678d7b2dd6bf
  proposed: 2b8867199deccaa1242525df82e34ae6c3a11d195824c57af97d9fb29c966629
```

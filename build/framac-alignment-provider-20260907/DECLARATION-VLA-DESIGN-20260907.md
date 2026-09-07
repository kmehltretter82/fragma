# Next declaration/VLA correction: source-derived design

Read-only design, 2026-09-07. No compiler, analyzer, build or target execution
was performed for this note. The proposed outcomes still require the separate
fixed controls. This does not promote the private provider or Hexagon.

Reviewed source: `worktree-2/source/frama-c-33.0-Arsenic`, particularly
`src/kernel_internals/typing/cabs2cil.ml` SHA256
`9c5fea44e1324b81b41d3f87dac27dd314f8d650c70bea77924a76f0269228fa`,
and frozen typing patch `0004-clang-alignment-typing.patch` SHA256
`970278b7dfd73a2206649583b2743b93f6bde6a349364c16c145b7370b0edc37`.

## C11 presence and alignment are different facts

`solveAlignas` (cabs2cil:4021–4058) intentionally retains `Some expression`
for a valid zero or ignored high request. Keep that distinction from `None`:
zero effective alignment is not absence of a source alignment specifier.
The retained Clang 21.1.8 `SemaDeclAttr.cpp:4614–4665` validates the request,
allows C11 zero, caches its bit alignment and adds the attribute even when the
cache is zero. Invalid requests return before adding the attribute; the private
frontend currently aborts instead of reproducing all subsequent error recovery.

The current merge at cabs2cil:2559–2589 copies either available `valignas` into
the shared varinfo before preserving whether the new definition supplied one.
`createGlobal:8548–8556` already supplies `isadef` for both initialized and
tentative definitions. `alreadyDefined` is updated for initialized objects at
8636; tentative definitions are separately deferred at 8640 onwards.

Minimal forward correction to calibrate: under the opt-in policy, before
merging attributes, reject `isadef && oldvi.valignas <> None &&
vi.valignas = None`. Retain the old/new original expressions and locations for
diagnostics. Do not replace either expression with its effective integer.
Keep the existing reverse initialized-definition guard until its independent
controls confirm it. Do not substitute `oldvi.vdefined` for `alreadyDefined`:
that would conflate tentative and real definitions.

There is a specific source-provenance limitation: exact-tag 21.1.8
`SemaDecl.cpp` was unavailable locally and through the attempted web endpoints.
An [official historical LLVM source listing](https://www.llvm.org/reports/scan-build/report-SemaDecl.cpp-ActOnFinishFunctionBody-4-1.html)
corroborates three design distinctions: forward checking treats the current
tentative declaration as defining; the later-new-attribute check skips prior
tentative definitions; redeclaration comparison uses all aligned attributes,
substituting natural alignment for a zero maximum. This is not authenticated
21.1.8 behavior. Installed `clang/AST/Decl.h:1272–1313` independently distinguishes
declaration-only, tentative and real definitions. Therefore the after-order
tentative control must remain reference-observation, not a presumed rejection.

The current `Option.equal` over C11 contributions at cabs2cil:2546–2556 is also
too narrow as a general design. Keep original-C11 presence separate from a
comparison summary: maximum effective contribution from the declaration's C11
and GNU requests, with a zero total interpreted as that declaration's natural
type alignment. Compare summaries only at the appropriate C11 redeclaration
gate; GNU-only redeclarations have distinct inheritance rules. Preserve each
source request and validate it before combination. This proposal needs controls
for zero/ignored versus explicit natural alignment and mixed GNU/C11 requests.

The new 14-case extra inventory correctly separates initialized controls and
zero/ignored observations. `c11-missing-after-16` must also be an observation.
Additional later controls should cover zero/ignored versus explicit natural 4,
C11 zero plus GNU 16 versus C11 16, and an intervening unannotated extern
declaration. Do not change the unchanged 55-case inventory to add these.
The compound above-maximum control's two compiler categories must remain
separate: a forward presence fix does not establish equivalent error recovery.

## VLA lowering must not erase the source array

The source-derived risk is concrete but not yet a measured outcome:

- `isVariableSizedArray`, cabs2cil:5106–5135, evaluates the bound and substitutes
  a pointer declarator. `makeVarSizeVarInfo:4583–4600` then calls the normal
  variable/type/alignment constructor on that pointer.
- `createLocal:8938–8977` saves the bound and records only the dynamic allocation
  size in `varSizeArrays`. `EXPR_SIZEOF:5853–5873` consults that table.
- `EXPR_ALIGNOF:5893–5915` does not consult it; the private direct-variable query
  in cil.ml:3374–3390 consequently sees `vi.vtype`. A double-array's natural
  alignment can be lost in favor of pointer alignment. The int companion does
  not discriminate the two on this model.
- `TtypeofE`, cabs2cil:4467–4472, also returns the lowered expression type. A fix
  only to direct GNU `__alignof__(a)` must not claim that source `typeof(a)`,
  address/dereference, all declaration alignment or allocation semantics work.

Minimal provenance-preserving next step: associate the final alpha-converted
VLA varinfo with an explicit source-array origin record, alongside—not instead
of—the saved-size expression. Record the original declarator and location,
already-evaluated bound, original element/type attributes, and original
declaration GNU/C11 requests. Clear this per-function metadata with
`varSizeArrays` at cabs2cil:9303. Never evaluate the original bound again merely
to recover type/alignment information.

For the first bounded implementation, resolve only the proven direct-variable
GNU query at the Cabs expression boundary using that origin and the existing
policy-aware alignment calculation. An unqualified, one-dimensional,
scalar-element VLA can obtain its alignment base from its retained element type;
the literal double/int controls need no new bound evaluation. Do not overwrite
the lowered pointer's type or add a fabricated aligned attribute to it. Do not
replace dynamic `sizeof(a)` with a constant: it must retain its saved-bound
dependency and remain invalid in a static initializer.

Extending this to attributed/C11-aligned VLAs requires preserving the typed
original object type before pointer lowering and using it for `solveAlignas`
underalignment checks. Re-running `doType` on the raw original declarator risks
re-evaluating a side-effecting bound. Prefer a single typed-declarator pass whose
result is subsequently lowered, or an explicitly scoped origin representation
which reuses the already-typed bound. Unsupported forms must remain explicit
limitations, not inherit the pointer's alignment silently.

Required controls after the initial double/int pair: an effectful bound occurs
exactly once in retained AST/IR; GNU honored/ignored/no-argument requests;
C11 requests below the original array's natural alignment; fixed arrays and
pointers remain unchanged; nested/static initializers retain evaluated-local
and VLA-size rejection. These are later finite controls, not a claim of current
complete VLA or expression-context support.

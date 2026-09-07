"""Exactly 24 fixed, compile/parse-only VLA and static-local controls.

No imports or import-time actions. Each source has one uncalled function and
one fixed-size static ULL witness. Dynamic sizes are deliberately NOT witness
constants: automatic volatile sinks retain them for separate raw AST/IR review.
Required outcomes express language intent, not observations or support claims.
"""


def inventory():
    guard = ('_Static_assert(__CHAR_BIT__ == 8 && sizeof(unsigned long long) == 8,\n'
             '               "fragma_alignment_u64_transport");\n')
    result = []

    def add(name, body, witness, intent, *, required="accept-with-matching-constants",
            limitation=None, checks=()):
        declarations = '\n'.join('        ' + expression + ','
                                 for _, expression in witness)
        source = (guard + '/* Never linked or called; retain LLVM IR and printed C only. */\n'
                  + 'void fragma_scope(unsigned int n)\n{\n' + body
                  + '    static const unsigned long long fragma_alignment_witness['
                  + str(len(witness)) + '] __attribute__((used)) = {\n'
                  + declarations + '\n    };\n}\n')
        result.append({
            "fixture": name,
            "alignment": None,
            "fields": [field for field, _ in witness],
            "source": source,
            "intent": intent,
            "required_result": required,
            "candidate_limitation": limitation,
            "ast_ir_checks": list(checks),
            "dynamic_size_witness": name == "static-local-dynamic-vla-size",
        })

    direct = (
        ("array_expression_alignment", "__alignof__(fragma_array)"),
        ("array_type_alignment", "_Alignof(__typeof__(fragma_array))"),
        ("outer_sizeof_size", "sizeof(sizeof(fragma_array))"),
        ("pointer_type_alignment", "__alignof__(void *)"),
    )
    dynamic_sink = '    volatile unsigned long long fragma_runtime_size = sizeof(fragma_array);\n'
    declaration = '    double fragma_array[n];\n'

    add("vla-direct-double", declaration + dynamic_sink, direct,
        "Direct GNU alignment and typeof must use the array; direct sizeof stays dynamic.",
        checks=("The runtime size sink uses the original saved VLA bound, not pointer size.",
                "The static witness contains only constant queries; do not compare the dynamic sink as a constant."))

    add("vla-parenthesized-double", declaration
        + '    volatile unsigned long long fragma_runtime_size = sizeof(((fragma_array)));\n',
        (("array_expression_alignment", "__alignof__(((fragma_array)))"),
         ("array_type_alignment", "_Alignof(__typeof__(((fragma_array))))"),
         ("outer_sizeof_size", "sizeof(sizeof(((fragma_array))))"),
         ("pointer_type_alignment", "__alignof__(void *)")),
        "Ordinary parentheses preserve direct-array provenance for all three queries.",
        checks=("The parenthesized runtime size uses the saved bound; parentheses do not decay the array.",))

    comma = (
        ("comma_expression_alignment", "__alignof__((0, fragma_array))"),
        ("comma_type_alignment", "_Alignof(__typeof__((0, fragma_array)))"),
        ("comma_expression_size", "sizeof((0, fragma_array))"),
        ("pointer_type_size", "sizeof(double *)"),
    )
    add("vla-comma-decay", declaration, comma,
        "A genuine comma expression decays the VLA to a pointer in all three queries.",
        checks=("No witness may regain original array alignment or dynamic allocation size after comma decay.",))

    add("vla-comma-unevaluated-increment", declaration,
        (("comma_expression_alignment", "__alignof__((n++, fragma_array))"),
         ("comma_type_alignment", "_Alignof(__typeof__((n++, fragma_array)))"),
         ("comma_expression_size", "sizeof((n++, fragma_array))"),
         ("pointer_type_size", "sizeof(double *)")),
        "The comma operands decay, but the increments in these fixed-result queries remain unevaluated.",
        checks=("No increment of n from a witness query may survive in retained AST or IR.",
                "Retain any compiler/analyzer unevaluated-expression warning; it is not permission to ignore other diagnostics."))

    add("vla-typeof-frozen-bound", declaration
        + '    n = 7;\n'
        + '    __typeof__(fragma_array) fragma_copy;\n'
        + dynamic_sink
        + '    volatile unsigned long long fragma_copy_size = sizeof(fragma_copy);\n',
        (("array_expression_alignment", "__alignof__(fragma_array)"),
         ("copy_expression_alignment", "__alignof__(fragma_copy)"),
         ("copy_type_alignment", "_Alignof(__typeof__(fragma_copy))"),
         ("pointer_type_alignment", "__alignof__(void *)")),
        "typeof must retain the original array and its frozen bound after n changes.",
        checks=("The copy is a VLA allocation, not an uninitialized pointer object.",
                "Both runtime sizes and the copy allocation reuse the original bound, not n=7.",
                "The dynamic size sinks are not constant witnesses, even if an optimizer simplifies a particular expression."))

    add("vla-effectful-bound-once", '    double fragma_array[n++];\n' + dynamic_sink,
        direct, "An effectful unsigned bound is evaluated exactly once and then reused.",
        checks=("Exactly one source post-increment of n is retained; later size/alignment/type queries add no increment.",
                "The array length is the pre-increment value and retains its target integral kind before range validation."))

    add("vla-volatile-bound-once", '    volatile unsigned int fragma_bound = n;\n'
        + '    double fragma_array[fragma_bound];\n' + dynamic_sink,
        direct, "A volatile bound is read once at the declaration, not again by subsequent queries.",
        checks=("Exactly one volatile read of fragma_bound supplies the saved length; its initialization store is not a read.",
                "The runtime size sink reuses the saved length and does not reread fragma_bound."))

    add("vla-fixed-inner-qualified", '    const double fragma_array[n][3];\n' + dynamic_sink,
        (("array_expression_alignment", "__alignof__(fragma_array)"),
         ("array_type_alignment", "_Alignof(__typeof__(fragma_array))"),
         ("fixed_row_type_size", "sizeof(const double [3])"),
         ("pointer_type_alignment", "__alignof__(void *)")),
        "An outer variable dimension retains its fixed inner array and const-qualified scalar elements.",
        checks=("The retained original type is an array of three const doubles per outer element.",
                "The lowered pointer targets a fixed row, and allocation/runtime size multiply the saved outer bound by row size.",
                "The constant row-size anchor alone does not prove qualifier preservation; inspect printed types."))

    for name, request, required, limitation, explanation in (
        ("zero", "0", "accept-with-matching-constants", None,
         "Zero remains an original C11 request without a stronger allocation requirement."),
        ("ignored-high", "536870912", "accept-with-matching-constants", None,
         "The original high request is retained even though its Clang bit-cache contribution is zero."),
        ("natural", "_Alignof(double)", "accept-with-matching-constants", None,
         "An honored natural request validates against the original array type."),
        ("underaligned", "_Alignof(double) / 2", "reject", None,
         "On the pinned Hexagon model this is a positive power of two below double alignment; reject against the original array."),
        ("stricter-allocation", "16", "accept-with-matching-constants",
         "valid-source-aligned-vla-allocation-not-yet-modeled",
         "Valid C11 alignment stronger than the natural element requirement needs an aligned allocation model, not a pointer attribute."),
    ):
        add("vla-c11-" + name,
            '    _Alignas(' + request + ') double fragma_array[n];\n' + dynamic_sink,
            direct, explanation, required=required, limitation=limitation,
            checks=("Retain the exact original C11 request and the genuine array type before lowering.",
                    "If accepted, direct GNU alignment must agree with the compiler while runtime sizeof remains dynamic."))

    for name, request, limitation, explanation in (
        ("natural", "__alignof__(double)", None,
         "A typed GNU request at natural alignment needs no stricter allocation model."),
        ("reduced", "4", None,
         "Measure the original GNU declaration's reduced expression alignment independently of natural element alignment."),
        ("ignored-high", "536870912", None,
         "A cache-ignored GNU request must not turn the original array query into a pointer query."),
        ("stricter-allocation", "16", "valid-source-aligned-vla-allocation-not-yet-modeled",
         "Compiler-valid stricter GNU alignment is an allocation-support gap, not an expected language rejection."),
    ):
        add("vla-gnu-" + name,
            '    double fragma_array[n] __attribute__((aligned(' + request + ')));\n'
            + dynamic_sink, direct, explanation, limitation=limitation,
            checks=("Retain the exact GNU source request on the original declaration; do not invent alignment on the synthetic pointer.",
                    "Expression alignment, type alignment, and actual allocation alignment are separate observations."))

    add("static-local-evaluated-value", '    unsigned int fragma_value = n;\n',
        (("invalid_local_value", "fragma_value"),),
        "A static witness cannot read an evaluated automatic local value.", required="reject",
        checks=("Require the actual initializer/local-reference diagnostic; arbitrary exit one is not a passing control.",))

    add("static-local-automatic-address", '    unsigned int fragma_value;\n',
        (("invalid_automatic_address", "(unsigned long long)&fragma_value"),),
        "The address of an automatic local is not a valid static initializer, even when cast to the witness integer type.",
        required="reject",
        checks=("Retain all address/constant-initializer diagnostics; do not confuse this with a global relocation constant.",))

    add("static-local-dynamic-vla-size", declaration,
        (("invalid_dynamic_array_size", "sizeof(fragma_array)"),),
        "A genuine VLA size must remain dynamic and invalid in a static witness.", required="reject",
        checks=("This deliberately invalid witness must not become sizeof(pointer) or any other constant after lowering.",))

    add("vla-nested-unevaluated-type-sizeof", '',
        (("outer_sizeof_size", "sizeof(sizeof(int[n]))"),
         ("sizeof_size_type", "sizeof(__typeof__(sizeof(int)))")),
        "The outer sizeof has a fixed integer operand type; a VLA type inside its unevaluated operand does not make it dynamic.",
        checks=("No VLA allocation or read of n may be introduced solely for these static constant queries.",))

    add("vla-pointer-type-sizeof", '',
        (("pointer_to_vla_size", "sizeof(int (*)[n])"),
         ("ordinary_pointer_size", "sizeof(int *)")),
        "A pointer type has fixed size even when its pointed-to array type has a variable bound.",
        checks=("Do not reject merely because a VLA occurs beneath a pointer type.",
                "No VLA object allocation is requested by sizeof this pointer type."))

    add("nonvla-comma-declaration-alignment", '    int fragma_object __attribute__((aligned(16)));\n',
        (("direct_expression_alignment", "__alignof__(fragma_object)"),
         ("comma_expression_alignment", "__alignof__((0, fragma_object))"),
         ("comma_type_alignment", "_Alignof(__typeof__((0, fragma_object)))"),
         ("comma_expression_size", "sizeof((0, fragma_object))")),
        "Comma expressions do not inherit even a non-VLA variable's declaration alignment.",
        checks=("The direct declaration query and comma result type must remain distinct observations.",))

    add("vla-nested-variable-dimensions", '    double fragma_array[n][n];\n' + dynamic_sink,
        direct, "Multiple variable dimensions are compiler-valid but exceed the current single-outer-dimension lowering.",
        limitation="valid-source-multiple-variable-dimensions-not-yet-modeled",
        checks=("Retain an explicit unsupported outcome; never accept a pointer-alignment fallback as the array result.",))

    return result

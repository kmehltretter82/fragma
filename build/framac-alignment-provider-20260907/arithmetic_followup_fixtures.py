"""Twenty fixed, pure compile/parse-only typed GNU alignment controls.

Only inventory() constructs data. No imports, I/O or import-time actions occur.
No function in the returned C sources is linked or called by this inventory;
calls and increments inside invalid attributes are source inputs, not actions.
Every witness has exactly three unsigned-long-long fields and a fixed bound.
Requirements are source-derived acceptance gates, never observed test results.
Warning/extension-sensitive compiler outcomes explicitly remain unknown.
"""


def inventory():
    guard = '''_Static_assert(__CHAR_BIT__ == 8 && sizeof(int) == 4 &&
               sizeof(unsigned int) == 4 && sizeof(unsigned long long) == 8,
               "fragma_typed_alignment_target_widths");
'''
    global_witness = '''const unsigned long long fragma_alignment_witness[3] = {
    sizeof(fragma_object), __alignof__(fragma_object),
    _Alignof(__typeof__(fragma_object))
};
'''
    local_witness = '''    static const unsigned long long fragma_alignment_witness[3]
        __attribute__((used)) = {
        sizeof(fragma_object), __alignof__(fragma_object),
        _Alignof(__typeof__(fragma_object))
    };
'''
    fields = ["object_size", "object_expression_alignment", "object_type_alignment"]

    def object_case(name, expression, intent, required, prefix=""):
        return {
            "fixture": "typed-gnu-" + name,
            "alignment": None,
            "fields": list(fields),
            "source": guard + prefix
                      + "extern int fragma_object __attribute__((aligned("
                      + expression + ")));\n" + global_witness,
            "intent": intent,
            "required_result": required,
            "expectation": ("unknown" if required == "reference-observation"
                            else "source-derived-not-observed"),
        }

    def local_case(name, expression, declarations, intent, required,
                   parameter="void", prefix=""):
        return {
            "fixture": "typed-gnu-" + name,
            "alignment": None,
            "fields": list(fields),
            "source": guard + prefix
                      + "/* Never called; retain IR and printed C only. */\n"
                      + "void fragma_scope(" + parameter + ")\n{\n"
                      + declarations
                      + "    int fragma_object __attribute__((aligned("
                      + expression + ")));\n" + local_witness + "}\n",
            "intent": intent,
            "required_result": required,
            "expectation": "source-derived-not-observed",
        }

    result = [
        object_case(
            "cast-truncation", "(unsigned char) 272U",
            "Preserve the unsigned-char cast: the original request becomes 16, not 272.",
            "accept-with-matching-constants"),
        object_case(
            "integer-promotions", "(unsigned char) 8 + (unsigned short) 8",
            "Apply C integer promotions before adding two narrow unsigned operands.",
            "accept-with-matching-constants"),
        object_case(
            "enum-shift", "FRAGMA_ALIGNMENT_BASE << 1",
            "Resolve and type an enum constant before a valid integer left shift.",
            "accept-with-matching-constants",
            "enum { FRAGMA_ALIGNMENT_BASE = 8 };\n"),
        object_case(
            "conditional-bitwise", "1 ? (((8U | 4U) ^ 4U) << 1) : 0U",
            "Fold bitwise operations and the selected conditional arm to 16; "
            "the unselected zero arm is not itself an alignment request.",
            "accept-with-matching-constants"),
        object_case(
            "unsigned-product-wrap-zero",
            "(unsigned int) 65536 * (unsigned int) 65536",
            "Target unsigned-int multiplication wraps to zero. Mathematical "
            "2^32 must not replace that invalid original C request. This is a "
            "cast/product control, distinct from the retained unsigned-addition case.",
            "reject"),
    ]

    for name, expression, intent in (
        ("signed-overflow", "2147483647 + 1",
         "Observe actual acceptance, warnings and value/category for signed "
         "addition overflow; do not assume the typed folder proves C validity."),
        ("signed-min-div-minus-one", "(-2147483647 - 1) / -1",
         "Observe signed-minimum divided by minus one, including every "
         "compiler warning/error rather than predicting extension behavior."),
        ("division-by-zero", "16 / 0",
         "Observe the compiler's complete constant-expression and division-by-zero "
         "diagnostics; a folded value alone cannot establish correspondence."),
        ("shift-by-width", "1U << 32",
         "Observe an unsigned shift count equal to the guarded 32-bit width; "
         "do not preclassify compiler warnings, rejection or extension folding."),
    ):
        result.append(object_case(name, expression, intent, "reference-observation"))

    result.extend([
        local_case(
            "sizeof-fixed-local", "sizeof(fragma_local)",
            "    int fragma_local[4];\n",
            "Use the unevaluated fixed local array size as a typed 16-byte "
            "request; hoisted printed attributes must not retain its local name.",
            "accept-with-matching-constants"),
        local_case(
            "alignof-fixed-local", "__alignof__(fragma_local)",
            "    double fragma_local;\n",
            "Use the unevaluated fixed double local's alignment as a typed "
            "request without evaluating an uninitialized local.",
            "accept-with-matching-constants"),
        local_case(
            "alignof-double-vla", "__alignof__(fragma_array)",
            "    double fragma_array[n];\n",
            "Combine 0006 original-array provenance with 0007 typed request "
            "conversion: double VLA alignment must not become pointer alignment. "
            "The dynamic bound exists only in the never-called function.",
            "accept-with-matching-constants", parameter="int n"),
    ])

    for order, requests in (
        ("high-then-low", ("(1U << 28) * 2U", "8U + 8U")),
        ("low-then-high", ("8U + 8U", "(1U << 28) * 2U")),
    ):
        result.append({
            "fixture": "typed-gnu-" + order,
            "alignment": None,
            "fields": list(fields),
            "source": guard + "extern int fragma_object __attribute__((aligned("
                      + requests[0] + "), aligned(" + requests[1] + ")));\n"
                      + global_witness,
            "intent": "Keep the original valid 2^29-byte arithmetic request "
                      "separate from its ignored cache contribution while "
                      "combining the honored 16-byte arithmetic request, " + order
                      + ". Printing must retain both original byte numbers; "
                      "zero is not a replacement for the high request.",
            "required_result": "accept-with-matching-constants",
            "expectation": "source-derived-not-observed",
            "original_requests_to_print": ([536870912, 16] if order == "high-then-low"
                                           else [16, 536870912]),
            "print_requirement": "Retain both original byte numerals on fragma_object; "
                                 "attribute reordering is not itself a mismatch.",
        })

    result.extend([
        local_case(
            "evaluated-local", "fragma_value", "",
            "An evaluated automatic parameter is not an integer constant "
            "expression, even if a folder could infer a convenient value.",
            "reject", parameter="int fragma_value"),
        local_case(
            "evaluated-address", "(unsigned long) &fragma_value",
            "    int fragma_value;\n",
            "Casting an automatic object's address to an integer must not "
            "create a valid constant alignment request or escaped local metadata.",
            "reject"),
        local_case(
            "evaluated-call", "fragma_request()", "",
            "An evaluated function call in an alignment argument must be "
            "rejected; no target function is linked or executed by this fixture.",
            "reject", prefix="extern unsigned int fragma_request(void);\n"),
        local_case(
            "evaluated-increment", "++fragma_value",
            "    int fragma_value = 8;\n",
            "An evaluated increment must not become a valid alignment through "
            "constant folding, discarded effects or declaration retyping.",
            "reject"),
    ])

    result.append({
        "fixture": "typed-gnu-forged-reserved-attribute-alias",
        "alignment": None,
        "fields": list(fields),
        "source": guard
                  + "extern int fragma_object __attribute__((\n"
                  + "    ___fc_clang_typed_alignment_request___(16, sizeof(int), \"forged\")));\n"
                  + global_witness,
        "intent": "Attempt direct source-level construction of private ACons "
                  "provenance through an underscore alias. The provider must "
                  "reject the reserved source attribute. Observe the compiler's "
                  "unknown-attribute handling without expecting matching rejection.",
        "required_result": "reference-observation",
        "expectation": "unknown",
        "analyzer_required_result": "reject-reserved-source-provenance",
    })
    result.append(object_case(
        "forged-provenance-call",
        "__fc_clang_typed_alignment_request(16, sizeof(int), \"forged\")",
        "An actual aligned argument containing a declared function call with "
        "the private marker's exact name must pass ordinary C typing and fail "
        "the constant/effect gate; its arguments are not trusted AST metadata.",
        "reject",
        "extern unsigned int __fc_clang_typed_alignment_request(\n"
        "    unsigned int, unsigned int, const char *);\n"))
    return result

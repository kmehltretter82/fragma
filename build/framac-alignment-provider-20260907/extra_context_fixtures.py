"""Fixed compile/parse-only controls; no imports or import-time execution.

All function bodies are inert inputs to the tools: none is linked or called.
Expectations describe source intent, not observed acceptance or semantic proof.
The compiler is the measured reference for the zero/ignored redeclaration cases.
"""


def inventory():
    guard = ('_Static_assert(__CHAR_BIT__ == 8 && sizeof(unsigned long long) == 8,\n'
             '               "fragma_alignment_u64_transport");\n')
    object_witness = '''const unsigned long long fragma_alignment_witness[] = {
    sizeof(fragma_object), __alignof__(fragma_object),
    _Alignof(__typeof__(fragma_object))
};
'''
    object_fields = ["object_size", "object_expression_alignment", "object_type_alignment"]
    result = []
    for order in ("before", "after"):
        for alignment in (16, 0, 2 ** 29):
            declaration = '_Alignas(FRAGMA_ALIGNMENT) extern int fragma_object;\n'
            definition = 'int fragma_object;\n'
            source = declaration + definition if order == "before" else definition + declaration
            result.append({
                "fixture": "c11-missing-" + order + "-" + str(alignment),
                "alignment": alignment, "fields": list(object_fields),
                "source": guard + source + object_witness,
                "intent": "Observe missing _Alignas on tentative definition, declaration "
                          + order + "; zero/ignored requests must not be assumed equivalent to 16.",
                "required_result": ("reject" if alignment == 16 and order == "before"
                                    else "reference-observation"),
            })
        declaration = '_Alignas(16) extern int fragma_object;\n'
        definition = 'int fragma_object = 0;\n'
        source = declaration + definition if order == "before" else definition + declaration
        result.append({
            "fixture": "c11-initialized-missing-" + order,
            "alignment": None, "fields": list(object_fields),
            "source": guard + source + object_witness,
            "intent": "Isolate initialized definition without _Alignas, declaration " + order + ".",
            "required_result": "reject",
        })
    for element in ("double", "int"):
        result.append({
            "fixture": "vla-" + element + "-alignment", "alignment": None,
            "fields": ["array_expression_alignment", "element_type_alignment", "pointer_type_alignment"],
            "source": guard + '''/* Never called; only LLVM IR and Frama-C printed C are retained. */
void fragma_scope(int n)
{
    ''' + element + ''' fragma_array[n];
    static const unsigned long long fragma_alignment_witness[] __attribute__((used)) = {
        __alignof__(fragma_array), __alignof__(''' + element + '''), __alignof__(void *)
    };
}
''',
            "intent": "Preserve original VLA element alignment after lowering; "
                      + ("double distinguishes array alignment from pointer alignment."
                         if element == "double" else "int is the non-discriminating companion control."),
            "required_result": "accept-with-matching-constants",
        })
    expressions = (
        ("addition", "8 + 8", "accept-with-matching-constants"),
        ("unsigned-wrap-zero", "0xffffffffU + 1", "reject"),
        ("negative", "-8", "reject"),
        ("nonpower", "8 + 4", "reject"),
    )
    for name, expression, required in expressions:
        result.append({
            "fixture": "gnu-arithmetic-" + name, "alignment": None,
            "fields": list(object_fields),
            "source": guard + 'extern int fragma_object __attribute__((aligned('
                      + expression + ')));\n' + object_witness,
            "intent": "Evaluate GNU request as target C, retaining original expression: " + expression,
            "required_result": required,
        })
    return result

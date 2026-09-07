/* FRAGMA: Frama-C front-end compatibility overrides.
 *
 * Force-included AFTER the kernel's own -include chain (compiler-version.h,
 * kconfig.h, compiler_types.h) but BEFORE the translation unit itself, so
 * #defines here override kernel macro definitions for all TU content.
 *
 * Note: __typeof_unqual__ cannot be handled here -- it appears in function
 * bodies inside early headers (asm-generic/rwonce.h) parsed before any
 * source include, so it is shimmed with -D on the command line instead.
 */
#ifndef FRAGMA_COMPAT_H
#define FRAGMA_COMPAT_H

/* Frama-C parses GCC extended asm, but not the "asm __inline" spelling. */
#undef asm_inline
#define asm_inline asm

#endif /* FRAGMA_COMPAT_H */

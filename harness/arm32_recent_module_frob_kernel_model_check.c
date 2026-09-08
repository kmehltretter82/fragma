/* SPDX-License-Identifier: GPL-2.0 */
/* Compile-only binding between the compact analysis model and the retained
 * configured ARM32 kernel headers.  It is not an executable test or proof of
 * the architecture hook.
 */
#include <linux/elf.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/types.h>
#include <asm/cache.h>
#include <asm/module.h>

#ifndef CONFIG_ARM_UNWIND
#error "module_frob model requires CONFIG_ARM_UNWIND"
#endif
#ifndef CONFIG_ARM_MODULE_PLTS
#error "module_frob model requires CONFIG_ARM_MODULE_PLTS"
#endif
#ifndef CONFIG_VMSPLIT_2G
#error "module_frob model requires CONFIG_VMSPLIT_2G"
#endif
#ifdef CONFIG_VMSPLIT_3G
#error "the retained branch must not use CONFIG_VMSPLIT_3G"
#endif
#ifdef CONFIG_DYNAMIC_FTRACE
#error "the compact fixed_plts model requires CONFIG_DYNAMIC_FTRACE=n"
#endif

_Static_assert(__CHAR_BIT__ == 8, "ARM32 eight-bit bytes");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
	       "retained ARM32 little-endian configuration");
_Static_assert(sizeof(unsigned long) == 4 && sizeof(void *) == 4,
	       "ARM32 long and pointer widths");
_Static_assert(__builtin_types_compatible_p(u32, unsigned int),
	       "exact u32 model type");
_Static_assert(__builtin_types_compatible_p(Elf32_Addr, unsigned int),
	       "exact Elf32_Addr model type");
_Static_assert(__builtin_types_compatible_p(Elf32_Off, unsigned int),
	       "exact Elf32_Off model type");
_Static_assert(__builtin_types_compatible_p(Elf32_Word, unsigned int),
	       "exact Elf32_Word model type");
_Static_assert(__builtin_types_compatible_p(Elf32_Half, unsigned short),
	       "exact Elf32_Half model type");

_Static_assert(sizeof(Elf32_Ehdr) == 52, "exact Elf32_Ehdr size");
_Static_assert(sizeof(Elf32_Shdr) == 40, "exact Elf32_Shdr size");
_Static_assert(sizeof(Elf32_Rel) == 8, "exact Elf32_Rel size");
_Static_assert(sizeof(Elf32_Sym) == 16, "exact Elf32_Sym size");
_Static_assert(__builtin_offsetof(Elf32_Shdr, sh_flags) == 8,
	       "exact Elf32_Shdr sh_flags offset");
_Static_assert(__builtin_offsetof(Elf32_Shdr, sh_info) == 28,
	       "exact Elf32_Shdr sh_info offset");

_Static_assert(ELF_SECTION_UNWIND == 0x70000001,
	       "exact ARM unwind section type");
_Static_assert(L1_CACHE_BYTES == 64, "retained ARM cache-line width");
_Static_assert(PLT_ENT_COUNT == 16, "exact PLT entry count");
_Static_assert(PLT_ENT_SIZE == 8, "exact PLT entry size");
_Static_assert(sizeof(struct plt_entries) == 128,
	       "exact PLT group size");
_Static_assert(sizeof(struct mod_plt_sec) == 12,
	       "exact compact PLT-section layout");
_Static_assert(__builtin_offsetof(struct mod_arch_specific, core) == 12,
	       "exact mod_arch_specific core offset");
_Static_assert(__builtin_offsetof(struct mod_arch_specific, init) == 24,
	       "exact mod_arch_specific init offset");
_Static_assert(sizeof(struct mod_arch_specific) == 36,
	       "exact mod_arch_specific size");

typedef int (*module_frob_fn)(Elf_Ehdr *, Elf_Shdr *, char *, struct module *);
_Static_assert(__builtin_types_compatible_p(typeof(&module_frob_arch_sections),
	       module_frob_fn), "exact module_frob_arch_sections signature");

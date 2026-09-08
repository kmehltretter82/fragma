/* SPDX-License-Identifier: GPL-2.0 */
/* Mechanically extracted from the pinned kernel source.  The provenance
 * gate compares the complete named declarator and body token-for-token.
 */
#include "arm32_recent_module_frob_model.h"
int module_frob_arch_sections(Elf_Ehdr *ehdr, Elf_Shdr *sechdrs,
			      char *secstrings, struct module *mod)
{
	unsigned long core_plts = ARRAY_SIZE(fixed_plts);
	unsigned long init_plts = ARRAY_SIZE(fixed_plts);
	Elf32_Shdr *s, *sechdrs_end = sechdrs + ehdr->e_shnum;
	Elf32_Sym *syms = NULL;

	/*
	 * To store the PLTs, we expand the .text section for core module code
	 * and for initialization code.
	 */
	for (s = sechdrs; s < sechdrs_end; ++s) {
		if (strcmp(".plt", secstrings + s->sh_name) == 0)
			mod->arch.core.plt = s;
		else if (strcmp(".init.plt", secstrings + s->sh_name) == 0)
			mod->arch.init.plt = s;
		else if (s->sh_type == SHT_SYMTAB)
			syms = (Elf32_Sym *)s->sh_addr;
#if defined(CONFIG_ARM_UNWIND) && !defined(CONFIG_VMSPLIT_3G)
		else if (s->sh_type == ELF_SECTION_UNWIND ||
			 (strncmp(".ARM.extab", secstrings + s->sh_name, 10) == 0)) {
			/*
			 * To avoid the possible relocation out of range issue for
			 * R_ARM_PREL31, mark unwind section .ARM.extab and .ARM.exidx as
			 * executable so they will be allocated along with .text section to
			 * meet +/-1GB range requirement of the R_ARM_PREL31 relocation
			 */
			s->sh_flags |= SHF_EXECINSTR;
		}
#endif
	}

	if (!mod->arch.core.plt || !mod->arch.init.plt) {
		pr_err("%s: module PLT section(s) missing\n", mod->name);
		return -ENOEXEC;
	}
	if (!syms) {
		pr_err("%s: module symtab section missing\n", mod->name);
		return -ENOEXEC;
	}

	for (s = sechdrs + 1; s < sechdrs_end; ++s) {
		Elf32_Rel *rels = (void *)ehdr + s->sh_offset;
		int numrels = s->sh_size / sizeof(Elf32_Rel);
		Elf32_Shdr *dstsec = sechdrs + s->sh_info;

		if (s->sh_type != SHT_REL)
			continue;

		/* ignore relocations that operate on non-exec sections */
		if (!(dstsec->sh_flags & SHF_EXECINSTR))
			continue;

		/* sort by type and symbol index */
		sort(rels, numrels, sizeof(Elf32_Rel), cmp_rel, NULL);

		if (!module_init_layout_section(secstrings + dstsec->sh_name))
			core_plts += count_plts(syms, dstsec->sh_addr, rels,
						numrels, s->sh_info);
		else
			init_plts += count_plts(syms, dstsec->sh_addr, rels,
						numrels, s->sh_info);
	}

	mod->arch.core.plt->sh_type = SHT_NOBITS;
	mod->arch.core.plt->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	mod->arch.core.plt->sh_addralign = L1_CACHE_BYTES;
	mod->arch.core.plt->sh_size = round_up(core_plts * PLT_ENT_SIZE,
					       sizeof(struct plt_entries));
	mod->arch.core.plt_count = 0;
	mod->arch.core.plt_ent = NULL;

	mod->arch.init.plt->sh_type = SHT_NOBITS;
	mod->arch.init.plt->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	mod->arch.init.plt->sh_addralign = L1_CACHE_BYTES;
	mod->arch.init.plt->sh_size = round_up(init_plts * PLT_ENT_SIZE,
					       sizeof(struct plt_entries));
	mod->arch.init.plt_count = 0;
	mod->arch.init.plt_ent = NULL;

	pr_debug("%s: plt=%x, init.plt=%x\n", __func__,
		 mod->arch.core.plt->sh_size, mod->arch.init.plt->sh_size);
	return 0;
}

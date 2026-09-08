/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded valid module image. No expected candidate return or output is
 * encoded: the first pass asks only for runtime-error and Eva alarms.
 */
#include "arm32_recent_module_frob_model.h"

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

int strcmp(const char *left, const char *right)
{
	while (*left && *left == *right) {
		left++;
		right++;
	}
	return (unsigned char)*left - (unsigned char)*right;
}

int strncmp(const char *left, const char *right, size_t count)
{
	while (count && *left && *left == *right) {
		left++;
		right++;
		count--;
	}
	if (!count)
		return 0;
	return (unsigned char)*left - (unsigned char)*right;
}

bool module_init_layout_section(const char *name)
{
	return strncmp(name, ".init", 5) == 0;
}

int cmp_rel(const void *left, const void *right)
{
	const Elf32_Rel *a = left;
	const Elf32_Rel *b = right;
	return a->r_info < b->r_info ? -1 : a->r_info > b->r_info;
}

/* Sorting and relocation-level PLT counting are dependencies, not claims in
 * this first candidate-orchestrator pass. Their intentionally narrow models
 * are recorded in the assumption ledger.
 */
void sort(void *base, size_t count, size_t size,
	  int (*cmp)(const void *, const void *),
	  void (*swap)(void *, void *, int))
{
	(void)base;
	(void)count;
	(void)size;
	(void)cmp;
	(void)swap;
}

unsigned int count_plts(const Elf32_Sym *symbols, Elf32_Addr base,
			const Elf32_Rel *relocations, int count,
			Elf32_Word destination_index)
{
	(void)symbols;
	(void)base;
	(void)relocations;
	(void)destination_index;
	if (count <= 0)
		return 0;
	return Frama_C_unsigned_int_interval(0, (unsigned int)count);
}

enum {
	FRAGMA_SECTION_COUNT = 11,
	FRAGMA_RELOCATION_COUNT = 8,
	FRAGMA_SYMBOL_COUNT = 8,
};

static char fragma_section_names[] =
	"\0.plt\0.init.plt\0.symtab\0.text\0.rel.text\0"
	".ARM.exidx.text\0.rel.ARM.exidx.text\0"
	".init.text\0.rel.init.text\0.ARM.extab.text\0";
static u32 fragma_text[16];
static Elf32_Sym fragma_symbols[FRAGMA_SYMBOL_COUNT];

struct fragma_module_image {
	Elf32_Ehdr header;
	Elf32_Rel core_relocations[FRAGMA_RELOCATION_COUNT];
	Elf32_Rel unwind_relocations[FRAGMA_RELOCATION_COUNT];
	Elf32_Rel init_relocations[FRAGMA_RELOCATION_COUNT];
};

static void fragma_arm32_module_frob_run(unsigned int untrusted_destination,
					 unsigned int relocation_count)
{
	struct fragma_module_image image = { 0 };
	Elf32_Shdr sections[FRAGMA_SECTION_COUNT] = { 0 };
	struct module module = { 0 };
	image.header.e_shnum = FRAGMA_SECTION_COUNT;

	sections[0].sh_type = SHT_NULL;

	/* Put the untrusted relocation section first so the concrete witness
	 * isolates its failing access from later safe loop iterations.
	 */
	sections[1].sh_name = 30;
	sections[1].sh_type = SHT_REL;
	sections[1].sh_addr = (Elf32_Addr)image.core_relocations;
	sections[1].sh_offset = (Elf32_Off)((char *)image.core_relocations -
					    (char *)&image.header);
	sections[1].sh_size = relocation_count * sizeof(Elf32_Rel);
	sections[1].sh_link = 3;
	sections[1].sh_info = untrusted_destination;

	sections[2].sh_name = 6;
	sections[2].sh_type = SHT_NOBITS;
	sections[2].sh_flags = SHF_ALLOC | SHF_EXECINSTR;

	sections[3].sh_name = 16;
	sections[3].sh_type = SHT_SYMTAB;
	sections[3].sh_addr = (Elf32_Addr)fragma_symbols;
	sections[3].sh_size = sizeof(fragma_symbols);

	sections[4].sh_name = 24;
	sections[4].sh_type = SHT_PROGBITS;
	sections[4].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	sections[4].sh_addr = (Elf32_Addr)fragma_text;
	sections[4].sh_size = sizeof(fragma_text);

	sections[5].sh_name = 1;
	sections[5].sh_type = SHT_NOBITS;
	sections[5].sh_flags = SHF_ALLOC | SHF_EXECINSTR;

	sections[6].sh_name = 40;
	sections[6].sh_type = ELF_SECTION_UNWIND;
	sections[6].sh_flags = SHF_ALLOC;
	sections[6].sh_addr = (Elf32_Addr)fragma_text;
	sections[6].sh_size = sizeof(fragma_text);

	sections[7].sh_name = 56;
	sections[7].sh_type = SHT_REL;
	sections[7].sh_addr = (Elf32_Addr)image.unwind_relocations;
	sections[7].sh_offset = (Elf32_Off)((char *)image.unwind_relocations -
					    (char *)&image.header);
	sections[7].sh_size = relocation_count * sizeof(Elf32_Rel);
	sections[7].sh_link = 3;
	sections[7].sh_info = 6;

	sections[8].sh_name = 76;
	sections[8].sh_type = SHT_PROGBITS;
	sections[8].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	sections[8].sh_addr = (Elf32_Addr)fragma_text;
	sections[8].sh_size = sizeof(fragma_text);

	sections[9].sh_name = 87;
	sections[9].sh_type = SHT_REL;
	sections[9].sh_addr = (Elf32_Addr)image.init_relocations;
	sections[9].sh_offset = (Elf32_Off)((char *)image.init_relocations -
					    (char *)&image.header);
	sections[9].sh_size = relocation_count * sizeof(Elf32_Rel);
	sections[9].sh_link = 3;
	sections[9].sh_info = 8;

	sections[10].sh_name = 102;
	sections[10].sh_type = SHT_PROGBITS;
	sections[10].sh_flags = SHF_ALLOC;
	sections[10].sh_addr = (Elf32_Addr)fragma_text;
	sections[10].sh_size = sizeof(fragma_text);

	(void)module_frob_arch_sections(&image.header, sections,
					fragma_section_names, &module);
}

void fragma_arm32_module_frob_arch_sections(void)
{
	unsigned int relocation_count = Frama_C_unsigned_int_interval(
		0, FRAGMA_RELOCATION_COUNT);
	/* elf_validity_cache_sechdrs() validates section contents and names but
	 * does not range-check sh_info before this architecture hook runs.
	 */
	unsigned int untrusted_destination =
		Frama_C_unsigned_int_interval(0, 0xffffffffU);

	/*@ assert arm32_module_frob_driver_domain:
	      relocation_count <= FRAGMA_RELOCATION_COUNT; */
	fragma_arm32_module_frob_run(untrusted_destination, relocation_count);
}

void fragma_arm32_module_frob_oob_witness(void)
{
	/* e_shnum is eleven, so this SHT_REL destination cannot name a section. */
	/*@ assert arm32_module_frob_witness_domain:
	      0x10000000U >= FRAGMA_SECTION_COUNT; */
	fragma_arm32_module_frob_run(0x10000000U, 1);
}

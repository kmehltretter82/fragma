/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal configured declarations for module_frob_arch_sections().
 * The source-identity gate covers the candidate; tests separately bind these
 * declarations and constants to the pinned ARM32 headers.
 */
#ifndef FRAGMA_ARM32_RECENT_MODULE_FROB_MODEL_H
#define FRAGMA_ARM32_RECENT_MODULE_FROB_MODEL_H

#include "arm32_recent_specs.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned int size_t;
typedef _Bool bool;

#define true 1
#define false 0
#define NULL ((void *)0)

typedef u32 Elf32_Addr;
typedef u16 Elf32_Half;
typedef u32 Elf32_Off;
typedef s32 Elf32_Sword;
typedef u32 Elf32_Word;

typedef struct elf32_rel {
	Elf32_Addr r_offset;
	Elf32_Word r_info;
} Elf32_Rel;

typedef struct elf32_sym {
	Elf32_Word st_name;
	Elf32_Addr st_value;
	Elf32_Word st_size;
	u8 st_info;
	u8 st_other;
	Elf32_Half st_shndx;
} Elf32_Sym;

#define EI_NIDENT 16
typedef struct elf32_hdr {
	u8 e_ident[EI_NIDENT];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct elf32_shdr {
	Elf32_Word sh_name;
	Elf32_Word sh_type;
	Elf32_Word sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off sh_offset;
	Elf32_Word sh_size;
	Elf32_Word sh_link;
	Elf32_Word sh_info;
	Elf32_Word sh_addralign;
	Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define ELF_SECTION_UNWIND 0x70000001
#define ENOEXEC 8

#define CONFIG_ARM_UNWIND 1
#define CONFIG_VMSPLIT_2G 1
#define CONFIG_ARM_MODULE_PLTS 1

#define L1_CACHE_BYTES 64
#define PLT_ENT_STRIDE L1_CACHE_BYTES
#define PLT_ENT_COUNT (PLT_ENT_STRIDE / sizeof(u32))
#define PLT_ENT_SIZE (sizeof(struct plt_entries) / PLT_ENT_COUNT)

struct plt_entries {
	u32 ldr[PLT_ENT_COUNT];
	u32 lit[PLT_ENT_COUNT];
};

struct mod_plt_sec {
	Elf32_Shdr *plt;
	struct plt_entries *plt_ent;
	int plt_count;
};

struct list_head {
	struct list_head *next, *prev;
};

struct unwind_table;
struct mod_arch_specific {
	struct list_head unwind_list;
	struct unwind_table *init_table;
	struct mod_plt_sec core;
	struct mod_plt_sec init;
};

struct module {
	struct mod_arch_specific arch;
};

/* DYNAMIC_FTRACE is disabled in the retained multi_v7 configuration. */
static const u32 fixed_plts[0];

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

#define pr_debug(...) ((void)0)
#define pr_err(...) ((void)0)

int strcmp(const char *left, const char *right);
int strncmp(const char *left, const char *right, size_t count);
bool module_init_layout_section(const char *name);
int cmp_rel(const void *left, const void *right);
void sort(void *base, size_t count, size_t size,
	  int (*cmp)(const void *, const void *),
	  void (*swap)(void *, void *, int));
unsigned int count_plts(const Elf32_Sym *symbols, Elf32_Addr base,
			const Elf32_Rel *relocations, int count,
			Elf32_Word destination_index);

int module_frob_arch_sections(Elf_Ehdr *ehdr, Elf_Shdr *sechdrs,
			      char *secstrings, struct module *mod);

#endif /* FRAGMA_ARM32_RECENT_MODULE_FROB_MODEL_H */

/* FRAGMA: RTE sweep of self-contained arithmetic leaves in
 * arch/riscv/kernel/ (rc6 HEAD, byte-identical to the rc4 build tree).
 *
 * Three leaves picked for pure shift/index/bounds arithmetic:
 *   1. fp_is_valid()          - stacktrace.c : frame-pointer window check
 *                               (sp + sizeof, ALIGN(sp, THREAD_SIZE), fp&7)
 *   2. riscv_kexec_elf_load() - kexec_elf.c  : per-phdr kbuf.mem/bufsz math
 *   3. elf_find_pbase()       - kexec_elf.c  : lowest paddr/vaddr + entry math
 *
 * Function bodies below are copied BYTE-IDENTICAL from the tree; only the
 * surrounding types/macros/stubs are supplied by this harness so WP/EVA can
 * see them without kernel headers.
 */

typedef unsigned char u8; typedef unsigned short u16;
typedef unsigned int u32; typedef unsigned long u64;
typedef signed int s32; typedef signed long s64; typedef unsigned long ulong;
typedef _Bool bool;
#define true 1
#define false 0
#define NULL ((void *)0)

/* ---- context for fp_is_valid --------------------------------------- */
struct stackframe {			/* asm/stacktrace.h: {fp, ra} => 16 bytes */
	unsigned long fp;
	unsigned long ra;
};
#define THREAD_SIZE  16384UL		/* PAGE_SIZE(4096) << THREAD_SIZE_ORDER(2) */
/* kernel ALIGN(x,a): round x up to a power-of-two 'a' */
#define __ALIGN_KERNEL_MASK(x, mask)  (((x) + (mask)) & ~(mask))
#define ALIGN(x, a)  __ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)

/* ==== VERBATIM from arch/riscv/kernel/stacktrace.c =================== */
static inline int fp_is_valid(unsigned long fp, unsigned long sp)
{
	unsigned long low, high;

	low = sp + sizeof(struct stackframe);
	high = ALIGN(sp, THREAD_SIZE);

	return !(fp < low || fp > high || fp & 0x07);
}
/* ==================================================================== */

/* ---- context for the kexec leaves ---------------------------------- */
#define PT_LOAD 1
#define PAGE_SIZE 4096UL
#define PMD_SIZE  (2UL * 1024 * 1024)
#define ULONG_MAX (~0UL)
#define KEXEC_BUF_MEM_UNKNOWN (~0UL)
#define min(a, b) ((a) < (b) ? (a) : (b))

struct kimage { unsigned long start; };

struct kexec_buf {
	struct kimage *image;
	void *buffer;
	unsigned long bufsz;
	unsigned long mem;
	unsigned long memsz;
	unsigned long buf_align;
	unsigned long buf_min;
	unsigned long buf_max;
	void *cma;
	bool top_down;
};

struct elf_phdr {			/* Elf64_Phdr fields used */
	u32 p_type;
	u64 p_offset;
	u64 p_paddr;
	u64 p_vaddr;
	u64 p_filesz;
	u64 p_memsz;
	u64 p_align;
};

struct elfhdr {				/* Elf64_Ehdr fields used */
	u64 e_entry;
	u16 e_phnum;
};

struct kexec_elf_info {
	const char *buffer;
	const struct elf_phdr *proghdrs;
};

/* stubs with contracts so WP stays local to the arithmetic under test */
/*@ assigns \nothing; ensures \result == 0 || \result == -1; */
int kexec_add_buffer(struct kexec_buf *kbuf);
/*@ assigns kbuf->mem; ensures \result == 0 || \result == -1; */
int arch_kexec_locate_mem_hole(struct kexec_buf *kbuf);

/* ==== VERBATIM from arch/riscv/kernel/kexec_elf.c =================== */
static int riscv_kexec_elf_load(struct kimage *image, struct elfhdr *ehdr,
				struct kexec_elf_info *elf_info, unsigned long old_pbase,
				unsigned long new_pbase)
{
	int i;
	int ret = 0;
	struct kexec_buf kbuf = {};
	const struct elf_phdr *phdr;

	kbuf.image = image;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &elf_info->proghdrs[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		kbuf.buffer = (void *) elf_info->buffer + phdr->p_offset;
		kbuf.bufsz = min(phdr->p_filesz, phdr->p_memsz);
		kbuf.buf_align = phdr->p_align;
		kbuf.mem = phdr->p_paddr - old_pbase + new_pbase;
		kbuf.memsz = phdr->p_memsz;
		kbuf.top_down = false;
		ret = kexec_add_buffer(&kbuf);
		if (ret)
			break;
	}

	return ret;
}

static int elf_find_pbase(struct kimage *image, unsigned long kernel_len,
			  struct elfhdr *ehdr, struct kexec_elf_info *elf_info,
			  unsigned long *old_pbase, unsigned long *new_pbase)
{
	int i;
	int ret;
	struct kexec_buf kbuf = {};
	const struct elf_phdr *phdr;
	unsigned long lowest_paddr = ULONG_MAX;
	unsigned long lowest_vaddr = ULONG_MAX;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = &elf_info->proghdrs[i];
		if (phdr->p_type != PT_LOAD)
			continue;

		if (lowest_paddr > phdr->p_paddr)
			lowest_paddr = phdr->p_paddr;

		if (lowest_vaddr > phdr->p_vaddr)
			lowest_vaddr = phdr->p_vaddr;
	}

	kbuf.image = image;
	kbuf.buf_min = lowest_paddr;
	kbuf.buf_max = ULONG_MAX;

	/*
	 * Current riscv boot protocol requires 2MB alignment for
	 * RV64 and 4MB alignment for RV32
	 *
	 */
	kbuf.buf_align = PMD_SIZE;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	kbuf.memsz = ALIGN(kernel_len, PAGE_SIZE);
	kbuf.cma = NULL;
	kbuf.top_down = false;
	ret = arch_kexec_locate_mem_hole(&kbuf);
	if (!ret) {
		*old_pbase = lowest_paddr;
		*new_pbase = kbuf.mem;
		image->start = ehdr->e_entry - lowest_vaddr + kbuf.mem;
	}
	return ret;
}
/* ==================================================================== */

void *fragma_keep[] = {
	(void *)fp_is_valid,
	(void *)riscv_kexec_elf_load,
	(void *)elf_find_pbase,
};

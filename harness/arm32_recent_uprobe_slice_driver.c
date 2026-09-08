/* SPDX-License-Identifier: GPL-2.0 */
/* Broad valid XOL-slot domain; no expected candidate result is encoded. */
#include "arm32_recent_uprobe_model.h"

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

static struct page fragma_uprobe_page;
static unsigned char fragma_uprobe_mapping[PAGE_SIZE];
static unsigned char fragma_uprobe_source[UPROBE_XOL_SLOT_BYTES];
static unsigned char fragma_uprobe_control_source[UPROBE_XOL_SLOT_BYTES + 1];

void *memcpy(void *destination, const void *source, unsigned long len)
{
	unsigned char *to = destination;
	const unsigned char *from = source;
	unsigned long index;

	for (index = 0; index < len; index++) {
		/*@ assert arm32_uprobe_copy_destination_valid:
		      \valid(to + index); */
		to[index] = from[index];
	}
	return destination;
}

void *kmap_local_page(const struct page *page)
{
	(void)page;
	return fragma_uprobe_mapping;
}

void kunmap_local(const void *address)
{
	(void)address;
}

void preempt_disable(void)
{
}

void preempt_enable(void)
{
}

void flush_uprobe_xol_access(struct page *page, unsigned long vaddr,
			     void *kaddr, unsigned long len)
{
	(void)page;
	(void)vaddr;
	(void)kaddr;
	(void)len;
}

void fragma_arm32_uprobe_copy_ixol(void)
{
	unsigned int slot = Frama_C_unsigned_int_interval(
		0, PAGE_SIZE / UPROBE_XOL_SLOT_BYTES - 1);
	unsigned long vaddr = slot * UPROBE_XOL_SLOT_BYTES;
	unsigned long len = Frama_C_unsigned_int_interval(
		0, UPROBE_XOL_SLOT_BYTES);

	/*@ assert arm32_uprobe_copy_ixol_driver_domain:
	      len <= UPROBE_XOL_SLOT_BYTES &&
	      vaddr + UPROBE_XOL_SLOT_BYTES <= PAGE_SIZE; */
	arch_uprobe_copy_ixol(&fragma_uprobe_page, vaddr,
			       fragma_uprobe_source, len);
}

/* Deliberately outside the in-tree 64-byte XOL-slot calling domain. */
void fragma_arm32_uprobe_copy_ixol_cross_page_control(void)
{
	unsigned long vaddr = PAGE_SIZE - UPROBE_XOL_SLOT_BYTES;
	unsigned long len = UPROBE_XOL_SLOT_BYTES + 1;

	/*@ assert arm32_uprobe_cross_page_control_domain:
	      vaddr == PAGE_SIZE - UPROBE_XOL_SLOT_BYTES &&
	      len == UPROBE_XOL_SLOT_BYTES + 1; */
	arch_uprobe_copy_ixol(&fragma_uprobe_page, vaddr,
			       fragma_uprobe_control_source, len);
}

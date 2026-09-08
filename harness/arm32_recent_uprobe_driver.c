/* SPDX-License-Identifier: GPL-2.0 */
/* Domain derived from public declarations/callers before candidate review. */
#include <linux/mm.h>
#include <linux/uprobes.h>

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
static unsigned char fragma_uprobe_source[UPROBE_XOL_SLOT_BYTES];

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

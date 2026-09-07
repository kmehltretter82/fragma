/* SPDX-License-Identifier: GPL-2.0 */
/* Independent API-domain drivers for the recent-risk ARM32 campaign.
 *
 * This file deliberately contains no implementation copied from a selected
 * function.  Domains are derived from include/linux/ioport.h and the
 * allocate_resource() callback site in kernel/resource.c.  Candidate bodies
 * remain direct inputs from the pinned kernel snapshot.
 */

#include <linux/ioport.h>
#include <linux/pci.h>

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

void fragma_arm32_pcibios_align_resource(void)
{
	struct pci_dev device = { 0 };
	struct resource candidate = { 0 };
	struct resource empty = { 0 };
	resource_size_t base, span, size, align;
	unsigned int shift;

	/* Keep this first RTE pass below 2 GiB so construction itself cannot
	 * overflow.  Dedicated boundary drivers follow only after raw triage.
	 */
	base = Frama_C_unsigned_int_interval(0, 0x3fffffffU);
	span = Frama_C_unsigned_int_interval(0, 0x000fffffU);
	size = Frama_C_unsigned_int_interval(1, 0x000fffffU);
	shift = Frama_C_unsigned_int_interval(0, 20);
	align = (resource_size_t)1 << shift;

	empty.start = base;
	empty.end = base + span;
	candidate.start = (base + align - 1) & ~(align - 1);
	candidate.end = empty.end;
	candidate.flags = Frama_C_unsigned_int_interval(0, 1) ?
		IORESOURCE_IO : IORESOURCE_MEM;

	/* This is the shape passed by __find_resource_space(): candidate.start
	 * is ALIGN(empty.start, align), candidate.end is empty.end, and ALIGN
	 * has already passed its wraparound check.
	 */
	/*@ assert arm32_pcibios_align_domain:
	      1 <= size <= 0x000fffff &&
	      1 <= align <= 0x00100000 &&
	      empty.start <= empty.end &&
	      empty.start <= candidate.start &&
	      candidate.end == empty.end &&
	      candidate.start % align == 0; */
	(void)pcibios_align_resource(&device, &candidate, &empty, size, align);
}

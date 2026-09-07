/* SPDX-License-Identifier: GPL-2.0 */
/* Independent bounded valid-input driver; no expected result is encoded. */
#include "arm32_recent_pci_model.h"

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

static struct pci_host_bridge fragma_bridge;

static resource_size_t fragma_align_callback(struct pci_dev *dev,
					      const struct resource *res,
					      resource_size_t start,
					      resource_size_t size,
					      resource_size_t align)
{
	(void)dev;
	(void)res;
	(void)size;
	(void)align;
	return start;
}

struct pci_host_bridge *pci_find_host_bridge(struct pci_bus *bus)
{
	(void)bus;
	return &fragma_bridge;
}

resource_size_t pci_align_resource(struct pci_dev *dev,
				   const struct resource *res,
				   const struct resource *empty_res,
				   resource_size_t size,
				   resource_size_t align)
{
	(void)dev;
	(void)empty_res;
	(void)size;
	(void)align;
	return res->start;
}

void fragma_arm32_pcibios_align_resource(void)
{
	struct pci_bus bus = { 0 };
	struct pci_dev device = { .bus = &bus };
	struct resource candidate = { 0 };
	struct resource empty = { 0 };
	resource_size_t base, span, size, align;
	unsigned int shift;

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
	fragma_bridge.align_resource =
		Frama_C_unsigned_int_interval(0, 1) ? fragma_align_callback : 0;

	/* Eva's first pass needs only the independently selected scalar bounds;
	 * object validity follows from the local construction.  The additional
	 * power-of-two/alignment relation is reserved for a relational/WP pass.
	 */
	/*@ assert arm32_pcibios_scalar_domain:
	      1 <= size <= 0x000fffff &&
	      1 <= align <= 0x00100000; */
	(void)pcibios_align_resource(&device, &candidate, &empty, size, align);
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Mechanically extracted from the pinned kernel source.  The provenance
 * gate compares the complete named declarator and body token-for-token.
 */
#include "arm32_recent_pci_model.h"
resource_size_t pcibios_align_resource(void *data, const struct resource *res,
				       const struct resource *empty_res,
				       resource_size_t size,
				       resource_size_t align)
{
	struct pci_dev *dev = data;
	resource_size_t start = res->start;
	struct pci_host_bridge *host_bridge;

	if (res->flags & IORESOURCE_IO && start & 0x300)
		start = (start + 0x3ff) & ~0x3ff;

	host_bridge = pci_find_host_bridge(dev->bus);

	if (host_bridge->align_resource)
		return host_bridge->align_resource(dev, res,
				start, size, align);

	if (res->flags & IORESOURCE_MEM)
		return pci_align_resource(dev, res, empty_res, size, align);

	return start;
}

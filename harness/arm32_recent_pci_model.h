/* SPDX-License-Identifier: GPL-2.0 */
/* Minimal configured declarations for the pcibios_align_resource() slice.
 * Every selected spelling/value is checked against the pinned ARM32 headers.
 */
#ifndef FRAGMA_ARM32_RECENT_PCI_MODEL_H
#define FRAGMA_ARM32_RECENT_PCI_MODEL_H

#include "arm32_recent_specs.h"

typedef unsigned int resource_size_t;

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	unsigned long flags;
	unsigned long desc;
	struct resource *parent, *sibling, *child;
};

struct pci_bus {
	unsigned int fragma_cookie;
};

struct pci_dev {
	struct pci_bus *bus;
};

struct pci_host_bridge {
	resource_size_t (*align_resource)(struct pci_dev *dev,
			const struct resource *res,
			resource_size_t start,
			resource_size_t size,
			resource_size_t align);
};

#define IORESOURCE_IO  0x00000100UL
#define IORESOURCE_MEM 0x00000200UL

struct pci_host_bridge *pci_find_host_bridge(struct pci_bus *bus);
resource_size_t pci_align_resource(struct pci_dev *dev,
				   const struct resource *res,
				   const struct resource *empty_res,
				   resource_size_t size,
				   resource_size_t align);

resource_size_t pcibios_align_resource(void *data,
				       const struct resource *res,
				       const struct resource *empty_res,
				       resource_size_t size,
				       resource_size_t align);

#endif /* FRAGMA_ARM32_RECENT_PCI_MODEL_H */

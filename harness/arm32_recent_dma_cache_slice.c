/* SPDX-License-Identifier: GPL-2.0 */
/* Mechanically copied from the pinned kernel candidate; only static is removed. */
#include "arm32_recent_dma_cache_model.h"

void dma_cache_maint_page(phys_addr_t phys, size_t size,
	enum dma_data_direction dir,
	void (*op)(const void *, size_t, int))
{
	unsigned long offset = offset_in_page(phys);
	unsigned long pfn = __phys_to_pfn(phys);
	size_t left = size;

	/*
	 * A single sg entry may refer to multiple physically contiguous
	 * pages.  But we still need to process highmem pages individually.
	 * If highmem is not configured then the bulk of this loop gets
	 * optimized out.
	 */
	do {
		size_t len = left;
		void *vaddr;

		phys = __pfn_to_phys(pfn);
		if (PhysHighMem(phys)) {
			if (len + offset > PAGE_SIZE)
				len = PAGE_SIZE - offset;

			if (cache_is_vipt_nonaliasing()) {
				vaddr = kmap_atomic_pfn(pfn);
				op(vaddr + offset, len, dir);
				kunmap_atomic(vaddr);
			} else {
				struct page *page = phys_to_page(phys);

				vaddr = kmap_high_get(page);
				if (vaddr) {
					op(vaddr + offset, len, dir);
					kunmap_high(page);
				}
			}
		} else {
			phys += offset;
			vaddr = phys_to_virt(phys);
			op(vaddr, len, dir);
		}
		offset = 0;
		pfn++;
		left -= len;
	} while (left);
}

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FRAGMA_ARM32_RECENT_DMA_CACHE_MODEL_H
#define FRAGMA_ARM32_RECENT_DMA_CACHE_MODEL_H

typedef unsigned int size_t;
typedef unsigned int phys_addr_t;

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define FRAGMA_DMA_PAGE_COUNT 4
#define FRAGMA_DMA_HIGHMEM_FIRST_PFN 2
#define FRAGMA_DMA_PHYSICAL_BYTES (FRAGMA_DMA_PAGE_COUNT * PAGE_SIZE)

struct page {
	unsigned long model_pfn;
};

#define offset_in_page(phys) ((unsigned long)(phys) & ~PAGE_MASK)
#define __phys_to_pfn(phys) ((unsigned long)((phys) >> PAGE_SHIFT))
#define __pfn_to_phys(pfn) ((phys_addr_t)(pfn) << PAGE_SHIFT)
#define PhysHighMem(phys) fragma_phys_highmem(phys)

int fragma_phys_highmem(phys_addr_t phys);
int cache_is_vipt_nonaliasing(void);
void *kmap_atomic_pfn(unsigned long pfn);
void kunmap_atomic(const void *address);
struct page *phys_to_page(phys_addr_t phys);
void *kmap_high_get(const struct page *page);
void kunmap_high(struct page *page);
void *phys_to_virt(phys_addr_t phys);

void dma_cache_maint_page(phys_addr_t phys, size_t size,
			  enum dma_data_direction dir,
			  void (*op)(const void *, size_t, int));

#endif /* FRAGMA_ARM32_RECENT_DMA_CACHE_MODEL_H */

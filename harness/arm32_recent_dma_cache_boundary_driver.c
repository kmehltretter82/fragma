/* SPDX-License-Identifier: GPL-2.0 */
/* Concrete lowmem-to-highmem boundary witness for dma_cache_maint_page(). */
#include "arm32_recent_dma_cache_model.h"

#define FRAGMA_DMA_MAPPING_NONE 0
#define FRAGMA_DMA_MAPPING_DIRECT 1
#define FRAGMA_DMA_MAPPING_TEMPORARY 2
#define FRAGMA_DMA_HIGHMEM_START \
	__pfn_to_phys(FRAGMA_DMA_HIGHMEM_FIRST_PFN)

static unsigned char fragma_dma_page_mapping[PAGE_SIZE];
static unsigned char fragma_dma_direct_mapping[PAGE_SIZE];
static struct page fragma_dma_page;
static unsigned int fragma_dma_mapping_kind;
static phys_addr_t fragma_dma_mapping_phys;
static unsigned int fragma_dma_op_count;
static unsigned int fragma_dma_nonaliasing;
static unsigned int fragma_dma_high_mapping_present;

int fragma_phys_highmem(phys_addr_t phys)
{
	return __phys_to_pfn(phys) >= FRAGMA_DMA_HIGHMEM_FIRST_PFN;
}

int cache_is_vipt_nonaliasing(void)
{
	return fragma_dma_nonaliasing;
}

void *kmap_atomic_pfn(unsigned long pfn)
{
	fragma_dma_mapping_kind = FRAGMA_DMA_MAPPING_TEMPORARY;
	fragma_dma_mapping_phys = __pfn_to_phys(pfn);
	return fragma_dma_page_mapping;
}

void kunmap_atomic(const void *address)
{
	(void)address;
}

struct page *phys_to_page(phys_addr_t phys)
{
	fragma_dma_page.model_pfn = __phys_to_pfn(phys);
	return &fragma_dma_page;
}

void *kmap_high_get(const struct page *page)
{
	if (!fragma_dma_high_mapping_present)
		return (void *)0;
	fragma_dma_mapping_kind = FRAGMA_DMA_MAPPING_TEMPORARY;
	fragma_dma_mapping_phys = __pfn_to_phys(page->model_pfn);
	return fragma_dma_page_mapping;
}

void kunmap_high(struct page *page)
{
	(void)page;
}

void *phys_to_virt(phys_addr_t phys)
{
	fragma_dma_mapping_kind = FRAGMA_DMA_MAPPING_DIRECT;
	fragma_dma_mapping_phys = phys;
	return fragma_dma_direct_mapping;
}

void fragma_dma_cache_boundary_op(const void *address, size_t len, int dir)
{
	(void)address;
	(void)len;
	(void)dir;

	if (fragma_dma_mapping_kind == FRAGMA_DMA_MAPPING_DIRECT) {
		/* A direct-map cache operation must not include a highmem byte. */
		/*@ check arm32_dma_cache_direct_mapping_stays_lowmem:
		      fragma_dma_mapping_phys + len <=
		      FRAGMA_DMA_HIGHMEM_START; */
	}
	fragma_dma_op_count++;
}

static void fragma_dma_reset(unsigned int nonaliasing,
			     unsigned int high_mapping_present)
{
	fragma_dma_mapping_kind = FRAGMA_DMA_MAPPING_NONE;
	fragma_dma_mapping_phys = 0;
	fragma_dma_op_count = 0;
	fragma_dma_nonaliasing = nonaliasing;
	fragma_dma_high_mapping_present = high_mapping_present;
}

void fragma_arm32_dma_cache_low_to_high_witness(void)
{
	phys_addr_t phys = FRAGMA_DMA_HIGHMEM_START - 64;
	phys_addr_t high_phys = FRAGMA_DMA_HIGHMEM_START + PAGE_SIZE - 64;
	size_t size = 128;

	/*@ assert arm32_dma_cache_boundary_witness_domain:
	      phys == FRAGMA_DMA_HIGHMEM_START - 64 &&
	      phys < FRAGMA_DMA_HIGHMEM_START &&
	      phys + 64 == FRAGMA_DMA_HIGHMEM_START &&
	      offset_in_page(phys) == PAGE_SIZE - 64 &&
	      size == 128; */
	fragma_dma_reset(1, 1);
	dma_cache_maint_page(phys, size, DMA_TO_DEVICE,
			     fragma_dma_cache_boundary_op);
	/*@ assert arm32_dma_cache_boundary_witness_reached:
	      fragma_dma_mapping_kind == FRAGMA_DMA_MAPPING_DIRECT &&
	      fragma_dma_op_count == 1; */

	/* Reach both highmem cache classes and the no-existing-mapping path. */
	fragma_dma_reset(1, 1);
	dma_cache_maint_page(high_phys, size, DMA_TO_DEVICE,
			     fragma_dma_cache_boundary_op);
	/*@ assert arm32_dma_cache_high_nonaliasing_control:
	      fragma_dma_mapping_kind == FRAGMA_DMA_MAPPING_TEMPORARY &&
	      fragma_dma_op_count == 2; */

	fragma_dma_reset(0, 1);
	dma_cache_maint_page(high_phys, size, DMA_TO_DEVICE,
			     fragma_dma_cache_boundary_op);
	/*@ assert arm32_dma_cache_high_aliasing_mapped_control:
	      fragma_dma_mapping_kind == FRAGMA_DMA_MAPPING_TEMPORARY &&
	      fragma_dma_op_count == 2; */

	fragma_dma_reset(0, 0);
	dma_cache_maint_page(high_phys, size, DMA_TO_DEVICE,
			     fragma_dma_cache_boundary_op);
	/*@ assert arm32_dma_cache_high_aliasing_unmapped_control:
	      fragma_dma_mapping_kind == FRAGMA_DMA_MAPPING_NONE &&
	      fragma_dma_op_count == 0; */
}

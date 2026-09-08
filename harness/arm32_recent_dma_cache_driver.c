/* SPDX-License-Identifier: GPL-2.0 */
/* Broad four-page topology; no expected candidate result is encoded. */
#include "arm32_recent_dma_cache_model.h"

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

static unsigned char fragma_dma_page_mapping[PAGE_SIZE];
static unsigned char fragma_dma_direct_mapping[PAGE_SIZE];
static struct page fragma_dma_page;
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
	(void)pfn;
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
	(void)page;
	return fragma_dma_page_mapping;
}

void kunmap_high(struct page *page)
{
	(void)page;
}

void *phys_to_virt(phys_addr_t phys)
{
	(void)phys;
	return fragma_dma_direct_mapping;
}

void fragma_dma_cache_op(const void *address, size_t len, int dir)
{
	(void)address;
	(void)len;
	(void)dir;
}

void fragma_arm32_dma_cache_maint_page(void)
{
	unsigned int final_page = Frama_C_unsigned_int_interval(0, 1);
	unsigned long pfn;
	unsigned long offset;
	phys_addr_t phys;
	size_t size = Frama_C_unsigned_int_interval(0, PAGE_SIZE);
	enum dma_data_direction dir = Frama_C_unsigned_int_interval(
		DMA_BIDIRECTIONAL, DMA_FROM_DEVICE);

	if (final_page) {
		pfn = FRAGMA_DMA_PAGE_COUNT - 1;
		offset = 0;
	} else {
		pfn = Frama_C_unsigned_int_interval(0,
			FRAGMA_DMA_PAGE_COUNT - 2);
		offset = Frama_C_unsigned_int_interval(0, PAGE_SIZE - 1);
	}
	phys = __pfn_to_phys(pfn) + offset;

	fragma_dma_nonaliasing = Frama_C_unsigned_int_interval(0, 1);
	fragma_dma_high_mapping_present = Frama_C_unsigned_int_interval(0, 1);

	/*@ assert arm32_dma_cache_driver_domain:
	      phys < FRAGMA_DMA_PHYSICAL_BYTES &&
	      size <= PAGE_SIZE &&
	      phys + size <= FRAGMA_DMA_PHYSICAL_BYTES &&
	      DMA_BIDIRECTIONAL <= dir <= DMA_FROM_DEVICE; */
	dma_cache_maint_page(phys, size, dir, fragma_dma_cache_op);
}

/* SPDX-License-Identifier: GPL-2.0 */
/* Broad analyzer-first PTE domain; no expected candidate result is encoded. */
#include "arm32_recent_cache_model.h"

extern volatile int Frama_C_entropy_source;

/*@ requires order: min <= max;
    assigns \result \from min, max, Frama_C_entropy_source;
    assigns Frama_C_entropy_source \from Frama_C_entropy_source;
    ensures result_bounded: min <= \result <= max;
  @*/
extern unsigned int Frama_C_unsigned_int_interval(unsigned int min,
						   unsigned int max)
	__attribute__((FC_BUILTIN));

static struct page fragma_page;
static struct folio fragma_folio;
static struct address_space fragma_mapping;
static unsigned int fragma_cacheid;
static unsigned int fragma_pfn_is_valid;
static unsigned int fragma_folio_is_reserved;
static unsigned int fragma_mapping_is_valid;
static unsigned int fragma_dcache_flushes;
static unsigned int fragma_icache_flushes;

int cache_is_vipt_nonaliasing(void)
{
	return !!(fragma_cacheid & (1U << 1));
}

int cache_is_vipt_aliasing(void)
{
	return !!(fragma_cacheid & (1U << 2));
}

int pte_exec(pte_t pteval)
{
	return !(pte_val(pteval) & (1U << 9));
}

unsigned long pte_pfn(pte_t pteval)
{
	return pte_val(pteval) >> 12;
}

int pfn_valid(unsigned long pfn)
{
	(void)pfn;
	return (int)fragma_pfn_is_valid;
}

struct page *pfn_to_page(unsigned long pfn)
{
	(void)pfn;
	return &fragma_page;
}

struct folio *page_folio(struct page *page)
{
	(void)page;
	return &fragma_folio;
}

int folio_test_reserved(const struct folio *folio)
{
	(void)folio;
	return (int)fragma_folio_is_reserved;
}

struct address_space *folio_flush_mapping(struct folio *folio)
{
	(void)folio;
	return fragma_mapping_is_valid ? &fragma_mapping : NULL;
}

int test_bit(unsigned int nr, const unsigned long *address)
{
	return !!(*address & (1UL << nr));
}

void set_bit(unsigned int nr, unsigned long *address)
{
	*address |= 1UL << nr;
}

void __flush_dcache_folio(struct address_space *mapping, struct folio *folio)
{
	(void)mapping;
	(void)folio;
	fragma_dcache_flushes++;
}

void __flush_icache_all(void)
{
	fragma_icache_flushes++;
}

void fragma_arm32_sync_icache_dcache(void)
{
	pte_t pteval = { Frama_C_unsigned_int_interval(0, ~0U) };
	fragma_cacheid = Frama_C_unsigned_int_interval(0, 0x3fU);
	fragma_pfn_is_valid = Frama_C_unsigned_int_interval(0, 1);
	fragma_folio_is_reserved = Frama_C_unsigned_int_interval(0, 1);
	fragma_mapping_is_valid = Frama_C_unsigned_int_interval(0, 1);
	fragma_folio.flags.f = Frama_C_unsigned_int_interval(0, ~0U);
	fragma_dcache_flushes = 0;
	fragma_icache_flushes = 0;

	/*@ assert arm32_sync_icache_dcache_domain: 1; */
	__sync_icache_dcache(pteval);
}

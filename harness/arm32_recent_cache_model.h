/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FRAGMA_ARM32_RECENT_CACHE_MODEL_H
#define FRAGMA_ARM32_RECENT_CACHE_MODEL_H

typedef unsigned int u32;
typedef u32 pteval_t;
typedef struct { pteval_t pte; } pte_t;

typedef _Bool bool;

struct page {
	unsigned int model_id;
};

struct folio {
	struct {
		unsigned long f;
	} flags;
};

struct address_space {
	unsigned int model_id;
};

#ifndef NULL
#define NULL ((void *)0)
#endif

enum { PG_dcache_clean = 0 };

#define pte_val(x) ((x).pte)

int cache_is_vipt_nonaliasing(void);
int cache_is_vipt_aliasing(void);
int pte_exec(pte_t pteval);
unsigned long pte_pfn(pte_t pteval);
int pfn_valid(unsigned long pfn);
struct page *pfn_to_page(unsigned long pfn);
struct folio *page_folio(struct page *page);
int folio_test_reserved(const struct folio *folio);
struct address_space *folio_flush_mapping(struct folio *folio);
int test_bit(unsigned int nr, const unsigned long *address);
void set_bit(unsigned int nr, unsigned long *address);
void __flush_dcache_folio(struct address_space *mapping, struct folio *folio);
void __flush_icache_all(void);
void __sync_icache_dcache(pte_t pteval);

#endif /* FRAGMA_ARM32_RECENT_CACHE_MODEL_H */

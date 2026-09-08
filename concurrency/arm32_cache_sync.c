/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Mthread semantic pilot for ARM32 __sync_icache_dcache().
 *
 * The copied function below is token-identical to the pinned kernel source.
 * The positive model publishes PG_dcache_clean only after a completed flush.
 * FRAGMA_ARM32_CACHE_EARLY_SET_NEGATIVE changes test_bit() into an early
 * publication control, matching the ordering defect fixed upstream.
 */
#include <mthread.h>
#include <pthread.h>
#include <stdbool.h>

typedef unsigned int u32;
typedef u32 pteval_t;
typedef struct { pteval_t pte; } pte_t;

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

static pthread_t modeled_worker;
static __fc_mthread_id modeled_bit_lock;
static struct page modeled_page;
static struct folio modeled_folio;
static int modeled_thread_flush_completed[4];

static int cache_is_vipt_nonaliasing(void)
{
	return 0;
}

static int cache_is_vipt_aliasing(void)
{
	return 0;
}

static int pte_exec(pte_t pteval)
{
	return !(pteval.pte & (1U << 9));
}

static unsigned long pte_pfn(pte_t pteval)
{
	return pteval.pte >> 12;
}

static int pfn_valid(unsigned long pfn)
{
	(void)pfn;
	return 1;
}

static struct page *pfn_to_page(unsigned long pfn)
{
	(void)pfn;
	return &modeled_page;
}

static struct folio *page_folio(struct page *page)
{
	(void)page;
	return &modeled_folio;
}

static int folio_test_reserved(const struct folio *folio)
{
	(void)folio;
	return 0;
}

static struct address_space *folio_flush_mapping(struct folio *folio)
{
	(void)folio;
	return NULL;
}

static void set_bit(unsigned int nr, unsigned long *address);

static int test_bit(unsigned int nr, const unsigned long *address)
{
	int lock_result;
	int unlock_result;
	int result;

	lock_result = Frama_C_mutex_lock(modeled_bit_lock);
	if (lock_result == -1)
		return 0;
	result = !!(*address & (1UL << nr));
	unlock_result = Frama_C_mutex_unlock(modeled_bit_lock);
	(void)unlock_result;
#ifdef FRAGMA_ARM32_CACHE_EARLY_SET_NEGATIVE
	set_bit(nr, (unsigned long *)address);
#endif
	return result;
}

static void set_bit(unsigned int nr, unsigned long *address)
{
	__fc_mthread_id thread_id;
	int lock_result;
	int unlock_result;

	lock_result = Frama_C_mutex_lock(modeled_bit_lock);
	if (lock_result == -1)
		return;
	thread_id = Frama_C_thread_id();
	if (thread_id < 0 || thread_id >= 4) {
		unlock_result = Frama_C_mutex_unlock(modeled_bit_lock);
		(void)unlock_result;
		return;
	}
	/*@ assert arm32_cache_publish_after_local_flush: modeled_thread_flush_completed[thread_id] == 1; */
	*address |= 1UL << nr;
	unlock_result = Frama_C_mutex_unlock(modeled_bit_lock);
	(void)unlock_result;
}

static void __flush_dcache_folio(struct address_space *mapping,
				 struct folio *folio)
{
	__fc_mthread_id thread_id;

	(void)mapping;
	(void)folio;
	thread_id = Frama_C_thread_id();
	if (thread_id < 0 || thread_id >= 4)
		return;
	modeled_thread_flush_completed[thread_id] = 1;
}

static void __flush_icache_all(void)
{
}

void __sync_icache_dcache ( pte_t pteval ) { unsigned long pfn ; struct folio * folio ; struct address_space * mapping ; if ( cache_is_vipt_nonaliasing ( ) && ! pte_exec ( pteval ) ) return ; pfn = pte_pfn ( pteval ) ; if ( ! pfn_valid ( pfn ) ) return ; folio = page_folio ( pfn_to_page ( pfn ) ) ; if ( folio_test_reserved ( folio ) ) return ; if ( cache_is_vipt_aliasing ( ) ) mapping = folio_flush_mapping ( folio ) ; else mapping = NULL ; if ( ! test_bit ( PG_dcache_clean , & folio -> flags . f ) ) { __flush_dcache_folio ( mapping , folio ) ; set_bit ( PG_dcache_clean , & folio -> flags . f ) ; } if ( pte_exec ( pteval ) ) __flush_icache_all ( ) ; }

static void invoke_sync(void)
{
	pte_t pteval = { 0 };

	__sync_icache_dcache(pteval);
}

static void *worker(void *unused)
{
	(void)unused;
	invoke_sync();
	return 0;
}

int main(void)
{
	modeled_bit_lock = Frama_C_mutex_init("arm32-cache-bit");
	if (modeled_bit_lock <= 0)
		return 1;
	if (pthread_create(&modeled_worker, 0, worker, 0) != 0)
		return 2;
	invoke_sync();
	return 0;
}

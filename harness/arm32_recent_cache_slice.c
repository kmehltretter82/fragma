/* SPDX-License-Identifier: GPL-2.0 */
/* Mechanically normalized from the pinned kernel candidate. */
#include "arm32_recent_cache_model.h"

void __sync_icache_dcache ( pte_t pteval ) { unsigned long pfn ; struct folio * folio ; struct address_space * mapping ; if ( cache_is_vipt_nonaliasing ( ) && ! pte_exec ( pteval ) ) return ; pfn = pte_pfn ( pteval ) ; if ( ! pfn_valid ( pfn ) ) return ; folio = page_folio ( pfn_to_page ( pfn ) ) ; if ( folio_test_reserved ( folio ) ) return ; if ( cache_is_vipt_aliasing ( ) ) mapping = folio_flush_mapping ( folio ) ; else mapping = NULL ; if ( ! test_bit ( PG_dcache_clean , & folio -> flags . f ) ) { __flush_dcache_folio ( mapping , folio ) ; set_bit ( PG_dcache_clean , & folio -> flags . f ) ; } if ( pte_exec ( pteval ) ) __flush_icache_all ( ) ; }

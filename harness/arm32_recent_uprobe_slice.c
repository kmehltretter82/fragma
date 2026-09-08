/* SPDX-License-Identifier: GPL-2.0 */
/* Mechanically copied from the pinned kernel candidate. */
#include "arm32_recent_uprobe_model.h"

void arch_uprobe_copy_ixol(struct page *page, unsigned long vaddr,
			   void *src, unsigned long len)
{
	void *xol_page_kaddr = kmap_local_page(page);
	void *dst = xol_page_kaddr + (vaddr & ~PAGE_MASK);

	preempt_disable();

	/* Initialize the slot */
	memcpy(dst, src, len);

	/* flush caches (dcache/icache) */
	flush_uprobe_xol_access(page, vaddr, dst, len);

	preempt_enable();

	kunmap_local(xol_page_kaddr);
}

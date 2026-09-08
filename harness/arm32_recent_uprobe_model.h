/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FRAGMA_ARM32_RECENT_UPROBE_MODEL_H
#define FRAGMA_ARM32_RECENT_UPROBE_MODEL_H

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define UPROBE_XOL_SLOT_BYTES 64

struct page {
	unsigned int model_id;
};

void *kmap_local_page(const struct page *page);
void kunmap_local(const void *address);
void preempt_disable(void);
void preempt_enable(void);
void flush_uprobe_xol_access(struct page *page, unsigned long vaddr,
			     void *kaddr, unsigned long len);
void *memcpy(void *destination, const void *source, unsigned long len);
void arch_uprobe_copy_ixol(struct page *page, unsigned long vaddr,
			   void *src, unsigned long len);

#endif /* FRAGMA_ARM32_RECENT_UPROBE_MODEL_H */

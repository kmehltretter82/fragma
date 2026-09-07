/* SPDX-License-Identifier: GPL-2.0 */
/* Parse-only padding adaptation for the direct bios32.c Frama-C target. */
#ifndef FRAGMA_ARM32_RECENT_CACHE_H
#define FRAGMA_ARM32_RECENT_CACHE_H

#include_next <linux/cache.h>

/* Frama-C treats the genuine zero-length member as a flexible array and then
 * rejects embedding its struct before later fields.  None of the selected PCI
 * function's objects contain CACHELINE_PADDING; retain a named aligned member
 * solely so unrelated included MM declarations remain parseable.
 */
#undef CACHELINE_PADDING
#define CACHELINE_PADDING(name) \
	struct { char x[1]; } name __aligned(1 << INTERNODE_CACHE_SHIFT)

#endif /* FRAGMA_ARM32_RECENT_CACHE_H */

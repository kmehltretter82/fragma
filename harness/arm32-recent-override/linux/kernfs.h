/* SPDX-License-Identifier: GPL-2.0 */
/* Parse-only declaration adaptation for an unused kernfs lock-array type. */
#ifndef FRAGMA_ARM32_RECENT_KERNFS_H
#define FRAGMA_ARM32_RECENT_KERNFS_H

/* The pinned kernfs.h has exactly one CONFIG_SMP conditional: it sizes an
 * internal lock array through ilog2().  Frama-C retains the runtime branch of
 * that macro while evaluating the array bound.  Parse the UP-size declaration
 * and restore the genuine configured symbol immediately afterwards.  The
 * selected PCI function neither accesses nor constructs a kernfs object.
 */
#ifdef CONFIG_SMP
#define FRAGMA_ARM32_RECENT_RESTORE_CONFIG_SMP 1
#undef CONFIG_SMP
#endif

#include_next <linux/kernfs.h>

#ifdef FRAGMA_ARM32_RECENT_RESTORE_CONFIG_SMP
#define CONFIG_SMP 1
#undef FRAGMA_ARM32_RECENT_RESTORE_CONFIG_SMP
#endif

#endif /* FRAGMA_ARM32_RECENT_KERNFS_H */

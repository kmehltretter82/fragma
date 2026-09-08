// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>

static int fragma_sh_info_init(void)
{
	pr_info("fragma_sh_info: loaded\n");
	return 0;
}

static void fragma_sh_info_exit(void)
{
	pr_info("fragma_sh_info: unloaded\n");
}

module_init(fragma_sh_info_init);
module_exit(fragma_sh_info_exit);

MODULE_DESCRIPTION("PA-RISC module sh_info A/B control");
MODULE_LICENSE("GPL");

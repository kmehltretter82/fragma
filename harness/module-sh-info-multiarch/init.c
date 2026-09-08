// SPDX-License-Identifier: GPL-2.0
#include <nolibc.h>
#include <linux/reboot.h>

#ifndef FRAGMA_ARCH
#define FRAGMA_ARCH "unknown"
#endif

static int load_module_file(const char *path)
{
	int fd;
	int ret;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0)
		return -1;

	ret = __sysret(__nolibc_syscall3(__NR_finit_module, fd, "", 0));
	close(fd);
	return ret;
}

static int unload_test_module(void)
{
	return __sysret(__nolibc_syscall2(__NR_delete_module,
					  "fragma_sh_info", 0));
}

int main(void)
{
	int saved_errno;
	int ret;

	printf("FRAGMA_AB_BEGIN arch=%s\n", FRAGMA_ARCH);

	errno = 0;
	ret = load_module_file("/control.ko");
	saved_errno = errno;
	printf("FRAGMA_CONTROL_LOAD ret=%d errno=%d\n", ret, saved_errno);
	if (!ret) {
		errno = 0;
		ret = unload_test_module();
		saved_errno = errno;
		printf("FRAGMA_CONTROL_UNLOAD ret=%d errno=%d\n", ret,
		       saved_errno);
	}

	printf("FRAGMA_EVIL_LOAD_BEGIN\n");
	errno = 0;
	ret = load_module_file("/evil.ko");
	saved_errno = errno;
	printf("FRAGMA_EVIL_LOAD ret=%d errno=%d\n", ret, saved_errno);
	if (!ret) {
		errno = 0;
		ret = unload_test_module();
		saved_errno = errno;
		printf("FRAGMA_EVIL_UNLOAD ret=%d errno=%d\n", ret,
		       saved_errno);
	}

	printf("FRAGMA_AB_COMPLETE arch=%s\n", FRAGMA_ARCH);
	__nolibc_syscall0(__NR_sync);
	reboot(LINUX_REBOOT_CMD_RESTART);
	for (;;)
		;
}

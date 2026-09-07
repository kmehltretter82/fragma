/* SPDX-License-Identifier: MIT */
#ifndef FRAGMA_S390_NATIVE_SUPPORT_H
#define FRAGMA_S390_NATIVE_SUPPORT_H
/* Only integer/pointer ABI crossings; no hosted headers in the kernel object. */
void fragma_s390_expect(const char *name, int observed, int expected);
void fragma_s390_state(const unsigned char *bytes, unsigned int value);
#endif

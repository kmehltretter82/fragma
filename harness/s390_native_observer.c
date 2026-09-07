/* SPDX-License-Identifier: MIT
 * Hosted observer for one benign, fixed-input specification calibration.
 * This translation unit is separate from the configured kernel-side object.
 */
#include <stdio.h>
#include <stdlib.h>
#include "s390_native_support.h"

_Static_assert(__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__, "s390 native endian");
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "s390 LP64 observer");
_Static_assert(sizeof(unsigned int) == 4, "s390 u32 observer");
_Static_assert(sizeof(__WCHAR_TYPE__) == 2 && (char)-1 > 0, "kernel scalar flags");

void fragma_byte_order_calibration(void);

void fragma_s390_expect(const char *name, int observed, int expected)
{
    observed = !!observed;
    if (printf("{\"kind\":\"property\",\"name\":\"%s\",\"observed\":%s,\"expected\":%s}\n",
               name, observed ? "true" : "false", expected ? "true" : "false") < 0 ||
        observed != expected || fflush(stdout))
        exit(3);
}

void fragma_s390_state(const unsigned char *bytes, unsigned int value)
{
    if (printf("{\"kind\":\"state\",\"value\":%u,\"bytes\":[%u,%u,%u]}\n",
               value, (unsigned int)bytes[0], (unsigned int)bytes[1],
               (unsigned int)bytes[2]) < 0 || fflush(stdout))
        exit(3);
}

/* Volatile stores/loads make native layout a runtime memory observation,
 * separate from the helper's explicit shifts and byte accesses. */
void fragma_s390_native_layout(void)
{
    volatile unsigned int word = 0x01020304U;
    volatile unsigned char *bytes = (volatile unsigned char *)&word;
    unsigned int b0 = bytes[0], b1 = bytes[1], b2 = bytes[2], b3 = bytes[3];
    if (printf("{\"kind\":\"native-layout\",\"bits\":64,\"byte_order\":\"big\",\"word\":%u,\"bytes\":[%u,%u,%u,%u]}\n",
               word, b0, b1, b2, b3) < 0 || fflush(stdout) ||
        b0 != 1 || b1 != 2 || b2 != 3 || b3 != 4)
        exit(3);
}

int main(void)
{
    if (puts("{\"kind\":\"begin\",\"entry\":\"fragma_byte_order_calibration\"}") < 0)
        return 3;
    fragma_s390_native_layout();
    fragma_byte_order_calibration();
    if (puts("{\"kind\":\"normal-return\",\"entry\":\"fragma_byte_order_calibration\"}") < 0 ||
        fflush(stdout))
        return 3;
    return 0;
}

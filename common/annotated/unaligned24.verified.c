/* SPDX-License-Identifier: GPL-2.0 */
/* Shared common subset from Linux b9b3e33b70b71e516930117e21de3ad2a7723747.
 * Exactly four kernel helpers and two project-only round-trip witnesses.
 * Their source C, full-domain contracts, and intermediate assertions are
 * unchanged from s390/annotated/unaligned.verified.c. No 48-bit or TOD scope.
 * Per-profile acceptance requires fresh source, frontend, proof and calibration gates.
 * A caller must explicitly select the reviewed effective inline policy;
 * kernel-model-check.c checks it against genuine configured kernel headers.
 */
#include "inline-policy.h"
#define inline FRAGMA_COMMON24_INLINE

typedef unsigned char u8;
typedef unsigned int u32;
#include "byteproof.h"

/*@ requires readable: \valid_read(p + (0 .. 2));
    terminates \true;
    assigns \nothing;
    ensures decoded_value: \result == 65536 * (integer)p[0] + 256 * (integer)p[1] + p[2];
    ensures decoded_range: \result <= 16777215;
 */
static inline u32 __get_unaligned_be24(const u8 *p)
{
	/*@ assert decode_decompose_low: (p[0] << 16 | p[1] << 8 | p[2]) == ((p[0] << 16 | p[1] << 8 | p[2]) & 255) + 256 * ((p[0] << 16 | p[1] << 8 | p[2]) >> 8); */
	/*@ assert decode_decompose_middle: ((p[0] << 16 | p[1] << 8 | p[2]) >> 8) == (((p[0] << 16 | p[1] << 8 | p[2]) >> 8) & 255) + 256 * ((p[0] << 16 | p[1] << 8 | p[2]) >> 16); */
	/*@ assert extracted_high: ((p[0] << 16 | p[1] << 8 | p[2]) >> 16) == p[0]; */
	/*@ assert extracted_middle: (((p[0] << 16 | p[1] << 8 | p[2]) >> 8) & 255) == p[1]; */
	/*@ assert extracted_low: ((p[0] << 16 | p[1] << 8 | p[2]) & 255) == p[2]; */
	return p[0] << 16 | p[1] << 8 | p[2];
}

/*@ requires readable: \valid_read(p + (0 .. 2));
    terminates \true;
    assigns \nothing;
    ensures decoded_value: \result == (integer)p[0] + 256 * (integer)p[1] + 65536 * (integer)p[2];
    ensures decoded_range: \result <= 16777215;
 */
static inline u32 __get_unaligned_le24(const u8 *p)
{
	/*@ assert decode_decompose_low: (p[0] | p[1] << 8 | p[2] << 16) == ((p[0] | p[1] << 8 | p[2] << 16) & 255) + 256 * ((p[0] | p[1] << 8 | p[2] << 16) >> 8); */
	/*@ assert decode_decompose_middle: ((p[0] | p[1] << 8 | p[2] << 16) >> 8) == (((p[0] | p[1] << 8 | p[2] << 16) >> 8) & 255) + 256 * ((p[0] | p[1] << 8 | p[2] << 16) >> 16); */
	/*@ assert extracted_high: ((p[0] | p[1] << 8 | p[2] << 16) >> 16) == p[2]; */
	/*@ assert extracted_middle: (((p[0] | p[1] << 8 | p[2] << 16) >> 8) & 255) == p[1]; */
	/*@ assert extracted_low: ((p[0] | p[1] << 8 | p[2] << 16) & 255) == p[0]; */
	return p[0] | p[1] << 8 | p[2] << 16;
}

/*@ requires writable: \valid(p + (0 .. 2));
    terminates \true;
    assigns p[0 .. 2];
    ensures byte_0: \at(p,Pre)[0] == (val / 65536) % 256;
    ensures byte_1: \at(p,Pre)[1] == (val / 256) % 256;
    ensures byte_2: \at(p,Pre)[2] == val % 256;
 */
static inline void __put_unaligned_be24(const u32 val, u8 *p)
{
	/*@ assert decompose_low: (integer)val == (val & 255) + 256 * (integer)(val >> 8); */
	/*@ assert decompose_middle: (val >> 8) == ((val >> 8) & 255) + 256 * (integer)(val >> 16); */
	/*@ assert decompose_high: (val >> 16) == ((val >> 16) & 255) + 256 * (integer)(val >> 24); */
	*p++ = (val >> 16) & 0xff;
	*p++ = (val >> 8) & 0xff;
	*p++ = val & 0xff;
}

/*@ requires writable: \valid(p + (0 .. 2));
    terminates \true;
    assigns p[0 .. 2];
    ensures byte_0: \at(p,Pre)[0] == val % 256;
    ensures byte_1: \at(p,Pre)[1] == (val / 256) % 256;
    ensures byte_2: \at(p,Pre)[2] == (val / 65536) % 256;
 */
static inline void __put_unaligned_le24(const u32 val, u8 *p)
{
	/*@ assert decompose_low: (integer)val == (val & 255) + 256 * (integer)(val >> 8); */
	/*@ assert decompose_middle: (val >> 8) == ((val >> 8) & 255) + 256 * (integer)(val >> 16); */
	/*@ assert decompose_high: (val >> 16) == ((val >> 16) & 255) + 256 * (integer)(val >> 24); */
	*p++ = val & 0xff;
	*p++ = (val >> 8) & 0xff;
	*p++ = (val >> 16) & 0xff;
}

/* Project-only witnesses, not additional kernel functions. */

/*@ terminates \true;
    assigns \nothing;
    ensures roundtrip: \result == val % 16777216;
 */
u32 fragma_roundtrip_be24(u32 val)
{
	u8 bytes[3];
	__put_unaligned_be24(val, bytes);
	return __get_unaligned_be24(bytes);
}

/*@ terminates \true;
    assigns \nothing;
    ensures roundtrip: \result == val % 16777216;
 */
u32 fragma_roundtrip_le24(u32 val)
{
	u8 bytes[3];
	__put_unaligned_le24(val, bytes);
	return __get_unaligned_le24(bytes);
}

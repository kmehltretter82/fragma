/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Six unchanged explicit-byte C helpers from include/linux/unaligned.h,
 * Linux b9b3e33b70b71e516930117e21de3ad2a7723747.
 *
 * Model inventory: u8/u32/u64 are unsigned char/int/long long, respectively,
 * from include/asm-generic/int-ll64.h and its uapi counterpart. The inline
 * expansion below matches the selected configured kernel's compiler_types.h;
 * kernel-model-check.c checks it against those real headers. No external
 * function contracts, alignment substitutions, or assembly are used. Each byte
 * pointer needs only byte alignment and the stated extent.
 * The s390x compiler-derived machine model is checked separately by the suite.
 * Explicit-byte encoding is independent of native integer byte order; the
 * profile's separate compiled/EVA layout calibration checks native big endian.
 * The additional 24-bit annotations are proved intermediate facts, not new
 * preconditions. The original 48-bit contracts remain present but unresolved.
 */
#define inline inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
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

/*@ requires writable: \valid(p + (0 .. 5));
    terminates \true;
    assigns p[0 .. 5];
    ensures byte_0: \at(p,Pre)[0] == (val / 1099511627776) % 256;
    ensures byte_1: \at(p,Pre)[1] == (val / 4294967296) % 256;
    ensures byte_2: \at(p,Pre)[2] == (val / 16777216) % 256;
    ensures byte_3: \at(p,Pre)[3] == (val / 65536) % 256;
    ensures byte_4: \at(p,Pre)[4] == (val / 256) % 256;
    ensures byte_5: \at(p,Pre)[5] == val % 256;
 */
static inline void __put_unaligned_be48(const u64 val, u8 *p)
{
	*p++ = (val >> 40) & 0xff;
	*p++ = (val >> 32) & 0xff;
	*p++ = (val >> 24) & 0xff;
	*p++ = (val >> 16) & 0xff;
	*p++ = (val >> 8) & 0xff;
	*p++ = val & 0xff;
}

/*@ requires readable: \valid_read(p + (0 .. 5));
    terminates \true;
    assigns \nothing;
    ensures decoded_value: \result ==
      1099511627776 * (integer)p[0] + 4294967296 * (integer)p[1] +
      16777216 * (integer)p[2] + 65536 * (integer)p[3] + 256 * (integer)p[4] + p[5];
    ensures decoded_range: \result <= 281474976710655;
 */
static inline u64 __get_unaligned_be48(const u8 *p)
{
	return (u64)p[0] << 40 | (u64)p[1] << 32 | (u64)p[2] << 24 |
		p[3] << 16 | p[4] << 8 | p[5];
}

/* These proof witnesses are project code, not additional kernel functions.
 * Their calls discharge the helpers' readable/writable preconditions, and their
 * results depend on the separately proved decoder/encoder functional contracts.
 */

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

/*@ terminates \true;
    assigns \nothing;
    ensures roundtrip: \result == val % 281474976710656;
 */
u64 fragma_roundtrip_be48(u64 val)
{
	u8 bytes[6];
	__put_unaligned_be48(val, bytes);
	return __get_unaligned_be48(bytes);
}

/* The independent project-only EVA calibration remains in unaligned.acsl.c.
 * It is intentionally not a caller in this proof-only translation unit: its
 * separately analyzed call would otherwise leave the global callee readable
 * precondition pending even when every selected round-trip call is proved.
 */

/* SPDX-License-Identifier: GPL-2.0 */
/* Compiler-only fixed-input observations of genuine pinned kernel helpers.
 * No emitted object is linked or executed. These checks are not runtime
 * reachability, an ACSL proof, or a replacement for native evidence.
 */
#include <linux/types.h>
#include <linux/unaligned.h>
#include <linux/build_bug.h>

#ifndef __OPTIMIZE__
#error "common24 calibration requires active compile-time checks"
#endif
#if !__has_attribute(__error__)
#error "common24 calibration requires the compiler error attribute"
#endif
#ifndef FRAGMA_COMMON24_EXPECT_BIG_ENDIAN
#error "common24 calibration requires an explicit expected byte order"
#elif FRAGMA_COMMON24_EXPECT_BIG_ENDIAN != 0 && FRAGMA_COMMON24_EXPECT_BIG_ENDIAN != 1
#error "invalid common24 expected byte order"
#endif
#ifndef FRAGMA_COMMON24_WRONG_CASE
#define FRAGMA_COMMON24_WRONG_CASE 0
#endif
#if FRAGMA_COMMON24_WRONG_CASE < 0 || FRAGMA_COMMON24_WRONG_CASE > 22
#error "unknown common24 calibration case"
#endif

/* A negative control changes exactly one expected value by one bit. It does
 * not change helper C, inputs, execution domain or the actual kernel macro.
 */
#define FRAGMA_CHECK(id, observed, expected, name) \
	BUILD_BUG_ON_MSG((observed) != ((expected) ^ \
		(FRAGMA_COMMON24_WRONG_CASE == (id))), "fragma common24 " name)

/* External definition and prototype: the compiler cannot drop all checks
 * merely because an unused static calibration function was never called.
 */
void fragma_common24_compiler_calibration(void);
void fragma_common24_compiler_calibration(void)
{
	const u8 input[3] = { 0x12, 0x34, 0x56 };
	u8 be[3], le[3], maximum[3], discarded[3];
	u32 word = 0x01020304U;
	const u8 *memory = (const u8 *)&word;

	FRAGMA_CHECK(1, __get_unaligned_be24(input), 0x123456U, "decode_be");
	FRAGMA_CHECK(2, __get_unaligned_le24(input), 0x563412U, "decode_le");
	__put_unaligned_be24(0xab123456U, be);
	__put_unaligned_le24(0xab123456U, le);
	FRAGMA_CHECK(3, be[0], 0x12U, "store_be_0");
	FRAGMA_CHECK(4, be[1], 0x34U, "store_be_1");
	FRAGMA_CHECK(5, be[2], 0x56U, "store_be_2");
	FRAGMA_CHECK(6, le[0], 0x56U, "store_le_0");
	FRAGMA_CHECK(7, le[1], 0x34U, "store_le_1");
	FRAGMA_CHECK(8, le[2], 0x12U, "store_le_2");
	FRAGMA_CHECK(9, __get_unaligned_be24(be), 0x123456U, "roundtrip_be");
	FRAGMA_CHECK(10, __get_unaligned_le24(le), 0x123456U, "roundtrip_le");
	__put_unaligned_be24(0xffffffffU, maximum);
	FRAGMA_CHECK(11, maximum[0], 0xffU, "maximum_be_0");
	FRAGMA_CHECK(12, maximum[1], 0xffU, "maximum_be_1");
	FRAGMA_CHECK(13, maximum[2], 0xffU, "maximum_be_2");
	FRAGMA_CHECK(14, __get_unaligned_be24(maximum), 0xffffffU, "maximum_roundtrip");
	__put_unaligned_le24(0x12000000U, discarded);
	FRAGMA_CHECK(15, discarded[0], 0U, "discarded_le_0");
	FRAGMA_CHECK(16, discarded[1], 0U, "discarded_le_1");
	FRAGMA_CHECK(17, discarded[2], 0U, "discarded_le_2");
	FRAGMA_CHECK(18, __get_unaligned_le24(discarded), 0U, "discarded_roundtrip");
	FRAGMA_CHECK(19, memory[0], FRAGMA_COMMON24_EXPECT_BIG_ENDIAN ? 1U : 4U, "memory_0");
	FRAGMA_CHECK(20, memory[1], FRAGMA_COMMON24_EXPECT_BIG_ENDIAN ? 2U : 3U, "memory_1");
	FRAGMA_CHECK(21, memory[2], FRAGMA_COMMON24_EXPECT_BIG_ENDIAN ? 3U : 2U, "memory_2");
	FRAGMA_CHECK(22, memory[3], FRAGMA_COMMON24_EXPECT_BIG_ENDIAN ? 4U : 1U, "memory_3");
}

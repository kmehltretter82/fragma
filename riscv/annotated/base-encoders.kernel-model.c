/* SPDX-License-Identifier: GPL-2.0 */
/* Real configured kernel headers, not the proof harness typedefs. The relative
 * snapshot path deliberately names the pinned source export in this project.
 */
#include <linux/types.h>
#include "../../build/sources/linux-b9b3e33b70b71/arch/riscv/net/bpf_jit.h"

_Static_assert(__riscv_xlen == 64 && sizeof(unsigned long) == 8, "riscv64 kernel ABI");
_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "configured byte order");
_Static_assert(__builtin_types_compatible_p(u8, unsigned char), "u8 model");
_Static_assert(__builtin_types_compatible_p(u16, unsigned short), "u16 model");
_Static_assert(__builtin_types_compatible_p(u32, unsigned int), "u32 model");
_Static_assert(sizeof(u8) == 1 && sizeof(u16) == 2 && sizeof(u32) == 4, "encoder widths");
_Static_assert(sizeof(int) == 4 && __CHAR_BIT__ == 8, "promotion and shift widths");
_Static_assert(__builtin_types_compatible_p(typeof((u8)0 << 25), int), "u8 promotion");
_Static_assert(__builtin_types_compatible_p(typeof((u16)0 << 20), int), "u16 promotion");
_Static_assert(__builtin_types_compatible_p(typeof((u32)0 << 12), unsigned int), "u32 shift type");

typedef u32 (*r_fn)(u8, u8, u8, u8, u8, u8);
typedef u32 (*i_fn)(u16, u8, u8, u8, u8);
typedef u32 (*u_fn)(u32, u8, u8);
typedef u32 (*amo_fn)(u8, u8, u8, u8, u8, u8, u8, u8);
_Static_assert(__builtin_types_compatible_p(typeof(&rv_r_insn), r_fn), "R declarator");
_Static_assert(__builtin_types_compatible_p(typeof(&rv_i_insn), i_fn), "I declarator");
_Static_assert(__builtin_types_compatible_p(typeof(&rv_s_insn), i_fn), "S declarator");
_Static_assert(__builtin_types_compatible_p(typeof(&rv_b_insn), i_fn), "B declarator");
_Static_assert(__builtin_types_compatible_p(typeof(&rv_u_insn), u_fn), "U declarator");
_Static_assert(__builtin_types_compatible_p(typeof(&rv_j_insn), u_fn), "J declarator");
_Static_assert(__builtin_types_compatible_p(typeof(&rv_amo_insn), amo_fn), "AMO declarator");

#define FRAGMA_STR_INNER(x) #x
#define FRAGMA_STR(x) FRAGMA_STR_INNER(x)
_Static_assert(__builtin_strcmp(FRAGMA_STR(inline),
	"inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((__no_instrument_function__))") == 0,
	"configured inline expansion");

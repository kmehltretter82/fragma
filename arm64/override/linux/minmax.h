/* FRAGMA: Frama-C-friendly replacement for linux/minmax.h.
 *
 * The real header implements min()/max()/clamp() with __auto_type and
 * statement expressions plus a large __careful_cmp type-safety scaffold that
 * Frama-C 33 cannot parse (no __auto_type).  For ANALYSIS the plain
 * conditional-expression forms are semantically identical (the elaborate
 * kernel versions exist only for compile-time type/overflow diagnostics and
 * double-evaluation avoidance, neither of which affects WP/EVA reasoning).
 *
 * Double-evaluation caveat: these macros evaluate their args twice.  That is
 * unsound ONLY if an argument has a side effect; none of the arithmetic-leaf
 * sweep targets pass side-effecting expressions to min/max, and a stray one
 * would surface as an assigns/effect mismatch, not a silent wrong result.
 */
#ifndef FRAGMA_MINMAX_H
#define FRAGMA_MINMAX_H

#define min(x, y)		((x) < (y) ? (x) : (y))
#define max(x, y)		((x) > (y) ? (x) : (y))
#define min_t(t, x, y)		((t)(x) < (t)(y) ? (t)(x) : (t)(y))
#define max_t(t, x, y)		((t)(x) > (t)(y) ? (t)(x) : (t)(y))
#define min3(x, y, z)		min((typeof(x))min(x, y), z)
#define max3(x, y, z)		max((typeof(x))max(x, y), z)
#define min_not_zero(x, y)	((x) == 0 ? (y) : ((y) == 0 ? (x) : min(x, y)))
#define clamp(v, lo, hi)	max((lo), min((v), (hi)))
#define clamp_t(t, v, lo, hi)	max_t(t, (lo), min_t(t, (v), (hi)))
#define clamp_val(v, lo, hi)	clamp_t(typeof(v), v, lo, hi)

/* array forms are unused by the sweep targets; provide safe fallbacks */
#define min_array(arr, n)	(arr)[0]
#define max_array(arr, n)	(arr)[0]

#endif /* FRAGMA_MINMAX_H */

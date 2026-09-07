/* FRAGMA: standalone RTE harness for the arm64 CPU-feature bitfield
 * extractors (arch/arm64/include/asm/cpufeature.h @ b9b3e33b70b71).
 *
 * Bodies are VERBATIM (check-verbatim.sh).  These are pure leaves over u64/int,
 * LP64 -> the x86_64 machdep models arm64's integer widths exactly.
 *
 * Each body has TWO shift-width UB hazards:
 *   features << (64 - width - field)   UB unless 0 <= 64-width-field <= 63
 *                                      i.e. 1 <= width+field <= 64
 *   (...)          >> (64 - width)      UB unless 0 <= 64-width <= 63
 *                                      i.e. 1 <= width <= 64
 * Combined precondition for definedness:
 *   width >= 1, field >= 0, width + field <= 64.
 * RTE proves the bodies clean under this; the caller audit then asks whether
 * anything passes width<=0 or field+width>64.
 */
typedef unsigned long long u64;
typedef signed long long   s64;

/*@ requires width_pos:   width >= 1;
    requires field_pos:   field >= 0;
    requires fits:        field + width <= 64;
    assigns \nothing;
  @*/
static int
cpuid_feature_extract_signed_field_width(u64 features, int field, int width)
{
	return (s64)(features << (64 - width - field)) >> (64 - width);
}

/*@ requires width_pos:   width >= 1;
    requires field_pos:   field >= 0;
    requires fits:        field + width <= 64;
    assigns \nothing;
  @*/
static unsigned int
cpuid_feature_extract_unsigned_field_width(u64 features, int field, int width)
{
	return (u64)(features << (64 - width - field)) >> (64 - width);
}

/* trivial address-taking so WP verifies both, not dead-code-eliminates them */
int (*fragma_s)(u64, int, int) = cpuid_feature_extract_signed_field_width;
unsigned int (*fragma_u)(u64, int, int) = cpuid_feature_extract_unsigned_field_width;

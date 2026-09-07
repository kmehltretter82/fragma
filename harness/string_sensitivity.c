/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded specification-sensitivity checks, not kernel defect reports.
 *
 * Link with the unchanged, source-checked annotated/string.verified.c TU.
 * Every entry is a separate EVA run. Positive facts precede exactly one
 * deliberately false assertion: propagation stopping there is expected.
 * All actual calls meet the selected normal-return API domains. No kernel
 * body, input-memory fault, concurrency, or assembly is introduced here.
 */
unsigned long strlcat(char *dest, const char *src, unsigned long count);
char *strnchr(const char *s, unsigned long count, int c);

void fragma_string_truncation(void)
{
	char dest[6] = {'a', 'b', 0, '!', '!', '!'};
	const char src[5] = "cdef";
	unsigned long result = strlcat(dest, src, 5);

	/*@ assert truncation_attempted_length: result == 6; */
	/*@ assert truncation_preserved_prefix: dest[0] == 'a' && dest[1] == 'b'; */
	/*@ assert truncation_exact_copy: dest[2] == 'c' && dest[3] == 'd'; */
	/*@ assert truncation_exact_nul: dest[4] == 0; */
	/*@ assert truncation_outside_capacity_unchanged: dest[5] == '!'; */
	/*@ assert truncation_source_unchanged: src[0] == 'c' && src[1] == 'd' && src[2] == 'e' && src[3] == 'f' && src[4] == 0; */
	/*@ assert return_is_stored_length_REFUTED: result == 4; */
}

void fragma_string_no_copy_room(void)
{
	char dest[3] = "ab";
	const char src[3] = "cd";
	unsigned long result = strlcat(dest, src, 3);

	/*@ assert no_room_attempted_length: result == 4; */
	/*@ assert no_room_preserved_string: dest[0] == 'a' && dest[1] == 'b' && dest[2] == 0; */
	/*@ assert every_nonempty_source_adds_byte_REFUTED: dest[2] == 'c'; */
}

void fragma_string_full_copy(void)
{
	char dest[4] = {0, '!', '!', '!'};
	const char src[3] = "cd";
	unsigned long result = strlcat(dest, src, 4);

	/*@ assert full_copy_attempted_length: result == 2; */
	/*@ assert full_copy_exact_bytes: dest[0] == 'c' && dest[1] == 'd'; */
	/*@ assert full_copy_exact_nul: dest[2] == 0; */
	/*@ assert full_copy_tail_unchanged: dest[3] == '!'; */
	/*@ assert reversed_copy_is_equivalent_REFUTED: dest[0] == 'd' && dest[1] == 'c'; */
}

void fragma_string_first_match(void)
{
	const char input[4] = {'a', 'b', 'a', 0};
	char *result = strnchr(input, 4, 'a');

	/*@ assert first_match_exact_pointer: result == input; */
	/*@ assert first_match_character: *result == 'a'; */
	/*@ assert any_matching_pointer_is_first_REFUTED: result == input + 2; */
}

void fragma_string_nul_conversion(void)
{
	const char input[2] = {'A', 0};
	char *result = strnchr(input, 8, 256);

	/*@ assert converted_character_is_nul: (char)256 == 0; */
	/*@ assert nul_after_conversion_found: result == input + 1; */
	/*@ assert nul_search_never_matches_REFUTED: result == \null; */
}

void fragma_string_early_nul(void)
{
	const char input[2] = {'A', 0};
	char *result = strnchr(input, 8, 'B');

	/*@ assert early_nul_returns_absent: result == \null; */
	/*@ assert early_nul_prefix_readable: \valid_read(input + (0 .. 1)); */
	/*@ assert full_count_storage_is_necessary_REFUTED: \valid_read(input + (0 .. 7)); */
}

void fragma_string_zero_count(void)
{
	const char *input = (const char *)0;
	char *result = strnchr(input, 0, 'A');

	/*@ assert zero_count_returns_null: result == \null; */
	/*@ assert zero_count_pointer_unchanged: input == \null; */
	/*@ assert zero_count_requires_readable_storage_REFUTED: \valid_read(input); */
}

void fragma_string_count_cutoff(void)
{
	const char input[3] = {'a', 'b', 'c'};
	char *result = strnchr(input, 2, 'c');

	/*@ assert count_cutoff_returns_absent: result == \null; */
	/*@ assert count_cutoff_input_readable: \valid_read(input + (0 .. 2)); */
	/*@ assert search_ignores_count_REFUTED: result == input + 2; */
}

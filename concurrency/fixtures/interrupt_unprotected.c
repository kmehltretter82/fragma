/* MODEL ONLY: calibration for automatic interrupt-handler registration.
 * The plain shared access is deliberately unprotected and would be a C data
 * race if interpreted as ordinary threads. The bounded assertion checks only
 * value interference; the expected race diagnostic is a separate outcome.
 */
static int interrupt_value;

void irq_handler(void)
{
	interrupt_value = 1;
}

int main(void)
{
	int observed = interrupt_value;

	/*@ assert interrupt_range: 0 <= observed && observed <= 1; */
	return observed;
}

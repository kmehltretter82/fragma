/* MODEL ONLY: tests whether an explicit Mthread mutex can protect accesses
 * between main and an automatically registered interrupt handler. This is a
 * provider calibration, not a model of Linux local_irq_disable(). The mutex
 * is initialized in main; the report must expose whether that is visible to
 * the independently started handler instead of assuming that it is.
 */
#include <mthread.h>

static __fc_mthread_id interrupt_lock;
static int interrupt_value;

void masked_irq_handler(void)
{
	if (Frama_C_mutex_lock(interrupt_lock) != 0)
		return;
	interrupt_value = 1;
	/*@ assert interrupt_handler_owned: interrupt_value == 1; */
	(void)Frama_C_mutex_unlock(interrupt_lock);
}

int main(void)
{
	interrupt_lock = Frama_C_mutex_init("interrupt-lock");
	if (interrupt_lock <= 0)
		return 1;
	if (Frama_C_mutex_lock(interrupt_lock) != 0)
		return 2;
	interrupt_value = 2;
	/*@ assert interrupt_main_owned: interrupt_value == 2; */
	(void)Frama_C_mutex_unlock(interrupt_lock);
	return 0;
}

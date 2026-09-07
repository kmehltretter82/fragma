/* MODEL ONLY: positive calibration for Mthread's abstract exclusion lock.
 * The worker stands in for an interrupt wrapper and is created only after the
 * abstract lock exists. This proves the provider can track that lock; it does
 * not prove automatic interrupt registration or Linux IRQ-mask semantics.
 */
#include <mthread.h>
#include <pthread.h>

static pthread_t interrupt_thread;
static __fc_mthread_id interrupt_lock;
static int interrupt_value;

static void *interrupt_worker(void *unused)
{
	(void)unused;
	if (Frama_C_mutex_lock(interrupt_lock) != 0)
		return 0;
	interrupt_value = 1;
	/*@ assert synthetic_interrupt_worker_owned: interrupt_value == 1; */
	(void)Frama_C_mutex_unlock(interrupt_lock);
	return 0;
}

int main(void)
{
	interrupt_lock = Frama_C_mutex_init("interrupt-lock");
	if (interrupt_lock <= 0)
		return 1;
	if (pthread_create(&interrupt_thread, 0, interrupt_worker, 0) != 0)
		return 2;
	if (Frama_C_mutex_lock(interrupt_lock) != 0)
		return 3;
	interrupt_value = 2;
	/*@ assert synthetic_interrupt_main_owned: interrupt_value == 2; */
	(void)Frama_C_mutex_unlock(interrupt_lock);
	return 0;
}

/* Synthetic negative control for Mthread+Eva; not a kernel bug.
 * The worker-local arithmetic is deterministic, while the assertion is
 * deliberately false. A useful baseline must identify it as Invalid rather
 * than treating exit status zero or successful parsing as acceptance.
 */
#include <pthread.h>

static pthread_t worker_thread;

static void *worker(void *unused)
{
	int value = 7;

	(void)unused;
	/*@ assert deliberate_false: value == 8; */
	return 0;
}

int main(void)
{
	if (pthread_create(&worker_thread, 0, worker, 0) != 0)
		return 1;
	return 0;
}

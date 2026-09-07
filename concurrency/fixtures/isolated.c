/* Synthetic Mthread analysis input; this fixture is not a runtime test.
 * The assertion concerns worker-local arithmetic only. No join or worker
 * completion guarantee is claimed when main returns.
 */
#include <pthread.h>

static pthread_t worker_thread;

static void *worker(void *unused)
{
	int value = 3;

	(void)unused;
	value = value * 2 + 1;
	/*@ assert isolated_arithmetic: value == 7; */
	return 0;
}

int main(void)
{
	if (pthread_create(&worker_thread, 0, worker, 0) != 0)
		return 1;
	return 0;
}

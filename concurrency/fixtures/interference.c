/* MODEL ONLY: synthetic input for abstract interference analysis.
 * Do not compile or execute: the deliberately unprotected plain shared
 * accesses are a C data race in a real threaded execution. Constant writes
 * keep the modeled values bounded; neither assertion demands an exact value
 * or is intended to be false. This fixture makes no completion claim.
 */
#include <pthread.h>

static pthread_t worker_thread;
static int shared_value;

static void *worker(void *unused)
{
	int observed;

	(void)unused;
	shared_value = 1;
	observed = shared_value;
	/*@ assert interference_worker_range: 0 <= observed && observed <= 2; */
	return 0;
}

int main(void)
{
	int observed;

	if (pthread_create(&worker_thread, 0, worker, 0) != 0)
		return 1;
	shared_value = 2;
	observed = shared_value;
	/*@ assert interference_main_range: 0 <= observed && observed <= 2; */
	return 0;
}

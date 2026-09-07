/* Synthetic model-gap diagnostic; this fixture is not a runtime test.
 * The bundled Mthread pthread_join stub returns a nondeterministic status
 * without waiting for its thread. The assertion records the completion
 * property wanted after a successful join; it does not assume the stub
 * establishes that property or prescribe an analyzer result.
 */
#include <pthread.h>

static pthread_t worker_thread;
static int join_completed;

static void *worker(void *unused)
{
	(void)unused;
	join_completed = 1;
	return 0;
}

int main(void)
{
	int observed;

	if (pthread_create(&worker_thread, 0, worker, 0) != 0)
		return 1;
	if (pthread_join(worker_thread, 0) != 0)
		return 2;
	observed = join_completed;
	/*@ assert join_completion_model_gap: observed == 1; */
	return 0;
}

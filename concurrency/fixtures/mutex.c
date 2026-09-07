/* Synthetic Mthread analysis input; this fixture is not a runtime test.
 * Every access to shared_value occurs after a successful lock. The assertions
 * concern the current critical section; no worker completion is claimed.
 */
#include <pthread.h>

static pthread_t worker_thread;
static pthread_mutex_t shared_mutex;
static int shared_value;
static int worker_failure;

static void *worker(void *unused)
{
	(void)unused;
	if (pthread_mutex_lock(&shared_mutex) != 0)
		return &worker_failure;
	shared_value = 1;
	/*@ assert mutex_worker_owned: shared_value == 1; */
	if (pthread_mutex_unlock(&shared_mutex) != 0)
		return &worker_failure;
	return 0;
}

int main(void)
{
	if (pthread_mutex_init(&shared_mutex, 0) != 0)
		return 1;
	if (pthread_create(&worker_thread, 0, worker, 0) != 0)
		return 2;
	if (pthread_mutex_lock(&shared_mutex) != 0)
		return 3;
	shared_value = 2;
	/*@ assert mutex_main_owned: shared_value == 2; */
	if (pthread_mutex_unlock(&shared_mutex) != 0)
		return 4;
	return 0;
}

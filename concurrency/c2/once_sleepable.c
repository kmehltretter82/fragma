/*
 * C2 model of the slow path behind DO_ONCE_SLEEPABLE().
 *
 * The two kernel function bodies below are copied from lib/once.c at the
 * pinned revision.  The C2 runner compares their token streams before using
 * this file.  Only Linux mutex exclusion between process-context callers is
 * abstracted with Mthread.  The static-key update is retained as data state,
 * but no static-branch or memory-ordering property is claimed.
 */
#include <mthread.h>
#include <pthread.h>
#include <stdbool.h>

struct module {
	int unused;
};

struct static_key_true {
	int enabled;
};

struct mutex {
	__fc_mthread_id id;
};

#define DEFINE_MUTEX(name) struct mutex name
#define __acquires(lock)
#define __releases(lock)
#define __acquire(lock) ((void)0)
#define EXPORT_SYMBOL(name)

#ifdef FRAGMA_C2_ELIDE_MUTEX_NEGATIVE
/* Deliberately non-excluding adapter used only by the required negative
 * control.  A C2 acceptance run is forbidden from defining this macro.
 */
static void mutex_lock(struct mutex *lock)
{
	Frama_C_mthread_show("negative lock elided", lock);
}

static void mutex_unlock(struct mutex *lock)
{
	Frama_C_mthread_show("negative unlock elided", lock);
}
#else
static void mutex_lock(struct mutex *lock)
{
	int result = Frama_C_mutex_lock(lock->id);

	/* The statically defined model lock is initialized before threads start. */
	/*@ assert c2_mutex_lock_succeeds: result != -1; */
}

static void mutex_unlock(struct mutex *lock)
{
	int result = Frama_C_mutex_unlock(lock->id);

	/* Every modeled unlock follows acquisition by the same task. */
	/*@ assert c2_mutex_unlock_succeeds: result != -1; */
}
#endif

static void static_branch_disable(struct static_key_true *key)
{
	/* The key only suppresses later slow-path calls.  Always taking the slow
	 * path is conservative for the selected done-access protection property.
	 */
	Frama_C_mthread_show("excluded static-key disable", key);
}

static DEFINE_MUTEX(once_mutex);

bool __do_once_sleepable_start(bool *done)
	__acquires(once_mutex)
{
	mutex_lock(&once_mutex);
	if (*done) {
		mutex_unlock(&once_mutex);
		/* Keep sparse happy by restoring an even lock count on
		 * this mutex. In case we return here, we don't call into
		 * __do_once_done but return early in the DO_ONCE_SLEEPABLE() macro.
		 */
		__acquire(once_mutex);
		return false;
	}

	/*@ assert c2_start_true_path_done_false: !*done; */
	return true;
}
EXPORT_SYMBOL(__do_once_sleepable_start);

void __do_once_sleepable_done(bool *done, struct static_key_true *once_key,
			 struct module *mod)
	__releases(once_mutex)
{
	*done = true;
	/*@ assert c2_done_published_before_unlock: *done; */
	mutex_unlock(&once_mutex);
	static_branch_disable(once_key);
}
EXPORT_SYMBOL(__do_once_sleepable_done);

static pthread_t worker_thread;
static bool modeled_done;
static struct static_key_true modeled_key = { 1 };
static struct module modeled_module;

static void invoke_once(void)
{
	if (__do_once_sleepable_start(&modeled_done)) {
		__do_once_sleepable_done(&modeled_done, &modeled_key,
					 &modeled_module);
	}
}

static void *worker(void *unused)
{
	(void)unused;
	invoke_once();
	return 0;
}

int main(void)
{
	once_mutex.id = Frama_C_mutex_init("linux-once-mutex");
	if (once_mutex.id <= 0)
		return 1;
	if (pthread_create(&worker_thread, 0, worker, 0) != 0)
		return 2;
	invoke_once();
	return 0;
}

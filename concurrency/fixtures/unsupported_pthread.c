/* Synthetic unsupported-semantics control; not a runtime test.
 * Frama-C 33's bundled Mthread pthread model declares barriers through the
 * libc header but supplies no Mthread stub. The expected outcome is an
 * explicit unsupported/possibly-unsound diagnostic, never acceptance.
 */
#include <pthread.h>

static pthread_barrier_t barrier;

int main(void)
{
	return pthread_barrier_wait(&barrier);
}

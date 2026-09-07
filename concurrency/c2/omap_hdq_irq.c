/*
 * C2 model of the OMAP HDQ irqstatus critical sections.
 *
 * The two marked Linux function bodies are copied from
 * drivers/w1/masters/omap_hdq.c at the pinned revision.  The runner compares
 * their C token streams.  MMIO, wait queues and logging are excluded; only
 * local hard-IRQ masking and the data spinlock are modeled here.  The handler
 * wrapper represents one post-initialization invocation.  On the same CPU it
 * owns the CPU/IRQ gate for the whole handler, while the remote-CPU case owns
 * only the driver spinlock around the source critical section.
 */
#include <mthread.h>
#include <pthread.h>
#include <stdbool.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef int irqreturn_t;

#define IRQ_HANDLED 1
#define BIT(value) (1U << (value))
#define OMAP_HDQ_INT_STATUS 0x10
#define OMAP_HDQ_INT_STATUS_TXCOMPLETE BIT(2)
#define OMAP_HDQ_INT_STATUS_RXCOMPLETE BIT(1)
#define OMAP_HDQ_INT_STATUS_TIMEOUT BIT(0)

struct device {
	int unused;
};

typedef struct {
	__fc_mthread_id id;
} spinlock_t;

struct hdq_data {
	struct device *dev;
	u8 hdq_irqstatus;
	spinlock_t hdq_spinlock;
};

static __fc_mthread_id modeled_cpu0_irq;
static bool modeled_process_critical;
static pthread_t modeled_irq_thread;
static struct device modeled_device;
static struct hdq_data modeled_hdq = {
	.dev = &modeled_device,
};
static int hdq_wait_queue;

static u8 hdq_reg_in(struct hdq_data *hdq_data, u32 offset)
{
	(void)hdq_data;
	(void)offset;
	return OMAP_HDQ_INT_STATUS_TXCOMPLETE;
}

#define dev_dbg(device, format, value) ((void)0)
#define wake_up(queue) Frama_C_mthread_show("excluded wait-queue wake", (queue))

static int model_spin_lock(spinlock_t *lock)
{
#ifdef FRAGMA_C2_IRQ_ELIDE_SPIN_NEGATIVE
	Frama_C_mthread_show("negative spin lock elided", lock);
	return 0;
#else
	return Frama_C_mutex_lock(lock->id);
#endif
}

static int model_spin_unlock(spinlock_t *lock)
{
#ifdef FRAGMA_C2_IRQ_ELIDE_SPIN_NEGATIVE
	Frama_C_mthread_show("negative spin unlock elided", lock);
	return 0;
#else
	return Frama_C_mutex_unlock(lock->id);
#endif
}

static void process_spin_lock_irqsave(spinlock_t *lock)
{
#ifdef FRAGMA_C2_IRQ_ELIDE_MASK_NEGATIVE
	Frama_C_mthread_show("negative process irq mask elided", lock);
#else
	int irq_result = Frama_C_mutex_lock(modeled_cpu0_irq);
	/*@ assert c2_irq_process_mask_lock_succeeds: irq_result != -1; */
#endif
	modeled_process_critical = true;
	int spin_result = model_spin_lock(lock);
	/*@ assert c2_irq_process_spin_lock_succeeds: spin_result != -1; */
}

static void process_spin_unlock_irqrestore(spinlock_t *lock)
{
	int spin_result = model_spin_unlock(lock);
	/*@ assert c2_irq_process_spin_unlock_succeeds: spin_result != -1; */
	modeled_process_critical = false;
#ifdef FRAGMA_C2_IRQ_ELIDE_MASK_NEGATIVE
	Frama_C_mthread_show("negative process irq restore elided", lock);
#else
	int irq_result = Frama_C_mutex_unlock(modeled_cpu0_irq);
	/*@ assert c2_irq_process_mask_unlock_succeeds: irq_result != -1; */
#endif
}

#define spin_lock_irqsave(lock, flags) \
	do { (flags) = 0; process_spin_lock_irqsave(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) \
	do { (void)(flags); process_spin_unlock_irqrestore(lock); } while (0)

/* BEGIN token-identical Linux function. */
static u8 hdq_reset_irqstatus(struct hdq_data *hdq_data, u8 bits)
{
	unsigned long irqflags;
	u8 status;

	spin_lock_irqsave(&hdq_data->hdq_spinlock, irqflags);
	status = hdq_data->hdq_irqstatus;
	/* this is a read-modify-write */
	hdq_data->hdq_irqstatus &= ~bits;
	spin_unlock_irqrestore(&hdq_data->hdq_spinlock, irqflags);

	return status;
}
/* END token-identical Linux function. */

#undef spin_lock_irqsave
#undef spin_unlock_irqrestore

static void handler_spin_lock_irqsave(spinlock_t *lock)
{
	int spin_result = model_spin_lock(lock);
	/*@ assert c2_irq_handler_spin_lock_succeeds: spin_result != -1; */
}

static void handler_spin_unlock_irqrestore(spinlock_t *lock)
{
	int spin_result = model_spin_unlock(lock);
	/*@ assert c2_irq_handler_spin_unlock_succeeds: spin_result != -1; */
}

#define spin_lock_irqsave(lock, flags) \
	do { (flags) = 0; handler_spin_lock_irqsave(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) \
	do { (void)(flags); handler_spin_unlock_irqrestore(lock); } while (0)

/* BEGIN token-identical Linux function. */
static irqreturn_t hdq_isr(int irq, void *_hdq)
{
	struct hdq_data *hdq_data = _hdq;
	unsigned long irqflags;

	spin_lock_irqsave(&hdq_data->hdq_spinlock, irqflags);
	hdq_data->hdq_irqstatus |= hdq_reg_in(hdq_data, OMAP_HDQ_INT_STATUS);
	spin_unlock_irqrestore(&hdq_data->hdq_spinlock, irqflags);
	dev_dbg(hdq_data->dev, "hdq_isr: %x\n", hdq_data->hdq_irqstatus);

	if (hdq_data->hdq_irqstatus &
		(OMAP_HDQ_INT_STATUS_TXCOMPLETE | OMAP_HDQ_INT_STATUS_RXCOMPLETE
		| OMAP_HDQ_INT_STATUS_TIMEOUT)) {
		/* wake up sleeping process */
		wake_up(&hdq_wait_queue);
	}

	return IRQ_HANDLED;
}
/* END token-identical Linux function. */

static void *hdq_irq_entry(void *unused)
{
	(void)unused;
#ifndef FRAGMA_C2_IRQ_REMOTE_CPU
	int irq_result = Frama_C_mutex_lock(modeled_cpu0_irq);
	bool process_active = modeled_process_critical;
	/*@ assert c2_irq_handler_entry_lock_succeeds: irq_result != -1; */
	/*@ assert c2_irq_same_cpu_no_overlap_boundary: !process_active; */
#endif
	(void)hdq_isr(0, &modeled_hdq);
#ifndef FRAGMA_C2_IRQ_REMOTE_CPU
	irq_result = Frama_C_mutex_unlock(modeled_cpu0_irq);
	/*@ assert c2_irq_handler_exit_unlock_succeeds: irq_result != -1; */
#endif
	return 0;
}

int main(void)
{
	modeled_cpu0_irq = Frama_C_mutex_init("cpu0-local-irq");
	if (modeled_cpu0_irq <= 0)
		return 1;
	modeled_hdq.hdq_spinlock.id = Frama_C_mutex_init("hdq-spinlock");
	if (modeled_hdq.hdq_spinlock.id <= 0)
		return 2;
	if (pthread_create(&modeled_irq_thread, 0, hdq_irq_entry, 0) != 0)
		return 3;
	(void)hdq_reset_irqstatus(&modeled_hdq,
			OMAP_HDQ_INT_STATUS_TXCOMPLETE);
	return 0;
}

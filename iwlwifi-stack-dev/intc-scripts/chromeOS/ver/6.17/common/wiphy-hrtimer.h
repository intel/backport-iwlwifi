#include <linux/hrtimer.h>

struct wiphy_hrtimer_work {
	struct wiphy_work work;
	struct wiphy *wiphy;
	struct hrtimer timer;
};

enum hrtimer_restart wiphy_hrtimer_work_timer(struct hrtimer *t);

static inline void wiphy_hrtimer_work_init(struct wiphy_hrtimer_work *hrwork,
					   wiphy_work_func_t func)
{
	hrtimer_setup(&hrwork->timer, wiphy_hrtimer_work_timer,
		      CLOCK_BOOTTIME, HRTIMER_MODE_REL);
	wiphy_work_init(&hrwork->work, func);
}

/**
 * wiphy_hrtimer_work_queue - queue hrtimer work for the wiphy
 * @wiphy: the wiphy to queue for
 * @hrwork: the high resolution timer worker
 * @delay: the delay given as a ktime_t
 *
 * Please refer to wiphy_delayed_work_queue(). The difference is that
 * the hrtimer work uses a high resolution timer for scheduling. This
 * may be needed if timeouts might be scheduled further in the future
 * and the accuracy of the normal timer is not sufficient.
 *
 * Expect a delay of a few milliseconds as the timer is scheduled
 * with some slack and some more time may pass between queueing the
 * work and its start.
 */
void wiphy_hrtimer_work_queue(struct wiphy *wiphy,
			      struct wiphy_hrtimer_work *hrwork,
			      ktime_t delay);

/**
 * wiphy_hrtimer_work_cancel - cancel previously queued hrtimer work
 * @wiphy: the wiphy, for debug purposes
 * @hrwork: the hrtimer work to cancel
 *
 * Cancel the work *without* waiting for it, this assumes being
 * called under the wiphy mutex acquired by wiphy_lock().
 */
void wiphy_hrtimer_work_cancel(struct wiphy *wiphy,
			       struct wiphy_hrtimer_work *hrtimer);

/**
 * wiphy_hrtimer_work_flush - flush previously queued hrtimer work
 * @wiphy: the wiphy, for debug purposes
 * @hrwork: the hrtimer work to flush
 *
 * Flush the work (i.e. run it if pending). This must be called
 * under the wiphy mutex acquired by wiphy_lock().
 */
void wiphy_hrtimer_work_flush(struct wiphy *wiphy,
			      struct wiphy_hrtimer_work *hrwork);

/**
 * wiphy_hrtimer_work_pending - Find out whether a wiphy hrtimer
 * work item is currently pending.
 *
 * @wiphy: the wiphy, for debug purposes
 * @hrwork: the hrtimer work in question
 *
 * Return: true if timer is pending, false otherwise
 *
 * Please refer to the wiphy_delayed_work_pending() documentation as
 * this is the equivalent function for hrtimer based delayed work
 * items.
 */
bool wiphy_hrtimer_work_pending(struct wiphy *wiphy,
				struct wiphy_hrtimer_work *hrwork);

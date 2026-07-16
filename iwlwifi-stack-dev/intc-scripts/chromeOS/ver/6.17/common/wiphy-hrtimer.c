enum hrtimer_restart wiphy_hrtimer_work_timer(struct hrtimer *t)
{
	struct wiphy_hrtimer_work *hrwork =
		container_of(t, struct wiphy_hrtimer_work, timer);

	wiphy_work_queue(hrwork->wiphy, &hrwork->work);

	return HRTIMER_NORESTART;
}
EXPORT_SYMBOL_GPL(wiphy_hrtimer_work_timer);

void wiphy_hrtimer_work_queue(struct wiphy *wiphy,
			      struct wiphy_hrtimer_work *hrwork,
			      ktime_t delay)
{
	if (!delay) {
		hrtimer_cancel(&hrwork->timer);
		wiphy_work_queue(wiphy, &hrwork->work);
		return;
	}

	hrwork->wiphy = wiphy;
	hrtimer_start_range_ns(&hrwork->timer, delay,
			       1000 * NSEC_PER_USEC, HRTIMER_MODE_REL);
}
EXPORT_SYMBOL_GPL(wiphy_hrtimer_work_queue);

void wiphy_hrtimer_work_cancel(struct wiphy *wiphy,
			       struct wiphy_hrtimer_work *hrwork)
{
	lockdep_assert_held(&wiphy->mtx);

	hrtimer_cancel(&hrwork->timer);
	wiphy_work_cancel(wiphy, &hrwork->work);
}
EXPORT_SYMBOL_GPL(wiphy_hrtimer_work_cancel);

void wiphy_hrtimer_work_flush(struct wiphy *wiphy,
			      struct wiphy_hrtimer_work *hrwork)
{
	lockdep_assert_held(&wiphy->mtx);

	hrtimer_cancel(&hrwork->timer);
	wiphy_work_flush(wiphy, &hrwork->work);
}
EXPORT_SYMBOL_GPL(wiphy_hrtimer_work_flush);

bool wiphy_hrtimer_work_pending(struct wiphy *wiphy,
				struct wiphy_hrtimer_work *hrwork)
{
	return hrtimer_is_queued(&hrwork->timer);
}
EXPORT_SYMBOL_GPL(wiphy_hrtimer_work_pending);

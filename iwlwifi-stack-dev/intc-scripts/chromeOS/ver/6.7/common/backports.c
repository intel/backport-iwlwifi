static void cfg80211_wiphy_work(struct work_struct *work)
{
	struct ieee80211_local *local;
	struct wiphy_work *wk;

	local = container_of(work, struct ieee80211_local, wiphy_work);

#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_lock();
#else
	wiphy_lock(local->hw.wiphy);
#endif
	if (local->suspended)
		goto out;

	spin_lock_irq(&local->wiphy_work_lock);
	wk = list_first_entry_or_null(&local->wiphy_work_list,
				      struct wiphy_work, entry);
	if (wk) {
		list_del_init(&wk->entry);
		if (!list_empty(&local->wiphy_work_list))
			schedule_work(work);
		spin_unlock_irq(&local->wiphy_work_lock);

		wk->func(local->hw.wiphy, wk);
	} else {
		spin_unlock_irq(&local->wiphy_work_lock);
	}
out:
#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_unlock();
#else
	wiphy_unlock(local->hw.wiphy);
#endif
}

void wiphy_work_setup(struct ieee80211_local *local)
{
	INIT_WORK(&local->wiphy_work, cfg80211_wiphy_work);
	INIT_LIST_HEAD(&local->wiphy_work_list);
	spin_lock_init(&local->wiphy_work_lock);
}

void wiphy_work_flush(struct wiphy *wiphy, struct wiphy_work *end)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ieee80211_local *local = hw_to_local(hw);
	struct wiphy_work *wk;
	unsigned long flags;
	int runaway_limit = 100;

	lockdep_assert_wiphy(wiphy);

	spin_lock_irqsave(&local->wiphy_work_lock, flags);
	if (end && list_empty(&end->entry))
		goto out;

	while (!list_empty(&local->wiphy_work_list)) {
		struct wiphy_work *wk;

		wk = list_first_entry(&local->wiphy_work_list,
				      struct wiphy_work, entry);
		list_del_init(&wk->entry);
		spin_unlock_irqrestore(&local->wiphy_work_lock, flags);

		wk->func(local->hw.wiphy, wk);

		spin_lock_irqsave(&local->wiphy_work_lock, flags);

		if (wk == end)
			break;

		if (WARN_ON(--runaway_limit == 0))
			INIT_LIST_HEAD(&local->wiphy_work_list);
	}
out:
	spin_unlock_irqrestore(&local->wiphy_work_lock, flags);
}
EXPORT_SYMBOL(wiphy_work_flush);

void wiphy_delayed_work_flush(struct wiphy *wiphy,
			      struct wiphy_delayed_work *dwork)
{
	del_timer_sync(&dwork->timer);
	wiphy_work_flush(wiphy, &dwork->work);
}
EXPORT_SYMBOL(wiphy_delayed_work_flush);

void wiphy_work_teardown(struct ieee80211_local *local)
{
#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_lock();
#else
	wiphy_lock(local->hw.wiphy);
#endif

	wiphy_work_flush(local->hw.wiphy, NULL);

#if LINUX_VERSION_IS_LESS(5,12,0)
	rtnl_unlock();
#else
	wiphy_unlock(local->hw.wiphy);
#endif

	cancel_work_sync(&local->wiphy_work);
}

void wiphy_work_queue(struct wiphy *wiphy, struct wiphy_work *work)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ieee80211_local *local = hw_to_local(hw);
	unsigned long flags;

	spin_lock_irqsave(&local->wiphy_work_lock, flags);
	if (list_empty(&work->entry))
		list_add_tail(&work->entry, &local->wiphy_work_list);
	spin_unlock_irqrestore(&local->wiphy_work_lock, flags);

	schedule_work(&local->wiphy_work);
}
EXPORT_SYMBOL_GPL(wiphy_work_queue);

void wiphy_work_cancel(struct wiphy *wiphy, struct wiphy_work *work)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct ieee80211_local *local = hw_to_local(hw);
	unsigned long flags;

#if LINUX_VERSION_IS_LESS(5,12,0)
	ASSERT_RTNL();
#else
	lockdep_assert_held(&wiphy->mtx);
#endif

	spin_lock_irqsave(&local->wiphy_work_lock, flags);
	if (!list_empty(&work->entry))
		list_del_init(&work->entry);
	spin_unlock_irqrestore(&local->wiphy_work_lock, flags);
}
EXPORT_SYMBOL_GPL(wiphy_work_cancel);

void wiphy_delayed_work_timer(struct timer_list *t)
{
	struct wiphy_delayed_work *dwork = from_timer(dwork, t, timer);

	wiphy_work_queue(dwork->wiphy, &dwork->work);
}
EXPORT_SYMBOL(wiphy_delayed_work_timer);

void wiphy_delayed_work_queue(struct wiphy *wiphy,
			      struct wiphy_delayed_work *dwork,
			      unsigned long delay)
{
	if (!delay) {
		del_timer(&dwork->timer);
		wiphy_work_queue(wiphy, &dwork->work);
		return;
	}

	dwork->wiphy = wiphy;
	mod_timer(&dwork->timer, jiffies + delay);
}
EXPORT_SYMBOL_GPL(wiphy_delayed_work_queue);

void wiphy_delayed_work_cancel(struct wiphy *wiphy,
			       struct wiphy_delayed_work *dwork)
{
#if LINUX_VERSION_IS_LESS(5,12,0)
	ASSERT_RTNL();
#else
	lockdep_assert_held(&wiphy->mtx);
#endif

	del_timer_sync(&dwork->timer);
	wiphy_work_cancel(wiphy, &dwork->work);
}
EXPORT_SYMBOL_GPL(wiphy_delayed_work_cancel);

void ieee80211_fragment_element(struct sk_buff *skb, u8 *len_pos, u8 frag_id)
{
	unsigned int elem_len;

	if (!len_pos)
		return;

	elem_len = skb->data + skb->len - len_pos - 1;

	while (elem_len > 255) {
		/* this one is 255 */
		*len_pos = 255;
		/* remaining data gets smaller */
		elem_len -= 255;
		/* make space for the fragment ID/len in SKB */
		skb_put(skb, 2);
		/* shift back the remaining data to place fragment ID/len */
		memmove(len_pos + 255 + 3, len_pos + 255 + 1, elem_len);
		/* place the fragment ID */
		len_pos += 255 + 1;
		*len_pos = frag_id;
		/* and point to fragment length to update later */
		len_pos++;
	}

	*len_pos = elem_len;
}
EXPORT_SYMBOL(ieee80211_fragment_element);

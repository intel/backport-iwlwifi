#define NL80211_EXT_FEATURE_PROT_RANGE_NEGO_AND_MEASURE -1

static inline bool cfg80211_any_usable_channels(struct wiphy *wiphy,
						unsigned long sband_mask,
						u32 prohibited_flags)
{
	int idx;

	prohibited_flags |= IEEE80211_CHAN_DISABLED;

	for_each_set_bit(idx, &sband_mask, NUM_NL80211_BANDS) {
		struct ieee80211_supported_band *sband = wiphy->bands[idx];
		int chanidx;

		if (!sband)
			continue;

		for (chanidx = 0; chanidx < sband->n_channels; chanidx++) {
			struct ieee80211_channel *chan;

			chan = &sband->channels[chanidx];

			if (chan->flags & prohibited_flags)
				continue;

			return true;
		}
	}

	return false;
}

/* make this code disappear, rfkill moved from rdev to wiphy */
#define rfkill_blocked(__rkfill) false

#ifndef PTR_IF
#define PTR_IF(cond, ptr)       ((cond) ? (ptr) : NULL)
#endif

#ifndef pm_sleep_ptr
#define pm_sleep_ptr(_ptr) PTR_IF(IS_ENABLED(CONFIG_PM_SLEEP), (_ptr))
#endif

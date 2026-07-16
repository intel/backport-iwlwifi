bool
ieee80211_uhb_power_type_valid(struct ieee80211_mgmt *mgmt, size_t len,
			       struct ieee80211_channel *channel);

ssize_t cfg80211_defragment_element(const struct element *elem, const u8 *ies,
				    size_t ieslen, u8 *data, size_t data_len,
				    u8 frag_id);

enum cfg80211_rnr_iter_ret {
	RNR_ITER_CONTINUE,
	RNR_ITER_BREAK,
	RNR_ITER_ERROR,
};

bool cfg80211_iter_rnr(const u8 *elems, size_t elems_len,
		       enum cfg80211_rnr_iter_ret
		       (*iter)(void *data, u8 type,
			       const struct ieee80211_neighbor_ap_info *info,
			       const u8 *tbtt_info, u8 tbtt_info_len),
		       void *iter_data);

#if LINUX_VERSION_IS_LESS(6,0,0)
#define cfg80211_ch_switch_notify(dev, chandef, link_id) cfg80211_ch_switch_notify(dev, chandef)
#else
#define cfg80211_ch_switch_notify(dev, chandef, link_id) cfg80211_ch_switch_notify(dev, chandef, link_id, 0)
#endif

#define NL80211_EXT_FEATURE_SPP_AMSDU_SUPPORT -1
#define ASSOC_REQ_SPP_AMSDU BIT(7)
#define NL80211_STA_FLAG_SPP_AMSDU 8
bool ieee80211_operating_class_to_chandef(u8 operating_class,
					  struct ieee80211_channel *chan,
					  struct cfg80211_chan_def *chandef);

#define IEEE80211_CHAN_CAN_MONITOR 0

int cfg80211_chandef_primary(const struct cfg80211_chan_def *chandef,
			     enum nl80211_chan_width primary_width,
			     u16 *punctured);

#if LINUX_VERSION_IS_LESS(5,11,0)
static inline void
LINUX_BACKPORT(cfg80211_ch_switch_started_notify)(struct net_device *dev,
						  struct cfg80211_chan_def *chandef,
						  unsigned int link_id, u8 count,
						  bool quiet)
{
	cfg80211_ch_switch_started_notify(dev, chandef, count);
}
#define cfg80211_ch_switch_started_notify LINUX_BACKPORT(cfg80211_ch_switch_started_notify)

#elif LINUX_VERSION_IS_LESS(6,1,0)
static inline void
LINUX_BACKPORT(cfg80211_ch_switch_started_notify)(struct net_device *dev,
						  struct cfg80211_chan_def *chandef,
						  unsigned int link_id, u8 count,
						  bool quiet)
{
	cfg80211_ch_switch_started_notify(dev, chandef, count, quiet);
}
#define cfg80211_ch_switch_started_notify LINUX_BACKPORT(cfg80211_ch_switch_started_notify)
#else
static inline void
LINUX_BACKPORT(cfg80211_ch_switch_started_notify)(struct net_device *dev,
						  struct cfg80211_chan_def *chandef,
						  unsigned int link_id, u8 count,
						  bool quiet)
{
	cfg80211_ch_switch_started_notify(dev, chandef, link_id, count, quiet, 0);
}
#define cfg80211_ch_switch_started_notify LINUX_BACKPORT(cfg80211_ch_switch_started_notify)
#endif

#ifdef CONFIG_THERMAL
#define THERMAL_TRIP_FLAG_RW_TEMP       BIT(0)
static inline struct thermal_zone_device *
backport_thermal_zone_device_register_with_trips(const char *type,
						 struct thermal_trip *trips,
						 int num_trips, void *devdata,
						 struct thermal_zone_device_ops *ops,
						 struct thermal_zone_params *tzp,
						 int passive_delay,
						 int polling_delay)
{
#if LINUX_VERSION_IS_LESS(6,0,0)
	return thermal_zone_device_register(type, num_trips, 0, devdata, ops, tzp,
					    passive_delay, polling_delay);
#else
#undef thermal_trip
	return thermal_zone_device_register_with_trips(type,
						       (struct thermal_trip *)(void *) trips,
						       num_trips,
						       0, devdata,
						       ops, tzp, passive_delay,
						       polling_delay);
#define thermal_trip backport_thermal_trip
#endif /* < 6,6,0 */
#define thermal_zone_device_register_with_trips LINUX_BACKPORT(thermal_zone_device_register_with_trips)
}

/* This function was added in 6,6,0 already, but struct thermal_trip isn't */
#if LINUX_VERSION_IS_GEQ(6,0,0)
#define for_each_thermal_trip LINUX_BACKPORT(for_each_thermal_trip)
static inline
int for_each_thermal_trip(struct thermal_zone_device *tz,
			  int (*cb)(struct thermal_trip *, void *),
			  void *data)
{
	struct thermal_trip *trip;
	struct thermal_trip *trips = (void *)tz->trips;
	int ret;

	for (trip = trips; trip - trips < tz->num_trips; trip++) {
		ret = cb(trip, data);
		if (ret)
			return ret;
	}

	return 0;
}
#endif /* >= 6,0,0 */
#endif /* CONFIG_THERMAL */

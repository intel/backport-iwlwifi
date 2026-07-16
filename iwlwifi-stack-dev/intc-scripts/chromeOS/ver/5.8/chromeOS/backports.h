#define NL80211_EXT_FEATURE_BEACON_PROTECTION_CLIENT -1
#define NL80211_EXT_FEATURE_CONTROL_PORT_OVER_NL80211_TX_STATUS -1
#define NL80211_EXT_FEATURE_SCAN_FREQ_KHZ -1

static inline __le16
ieee80211_get_he_6ghz_sta_cap(const struct ieee80211_supported_band *sband)
{
	return 0;
}

#if LINUX_VERSION_IS_LESS(5,4,0)
static inline bool cfg80211_channel_is_psc(struct ieee80211_channel *chan)
{
	return false;
}
#else
static inline bool cfg80211_channel_is_psc(struct ieee80211_channel *chan)
{
	if (chan->band != NL80211_BAND_6GHZ)
		return false;

	return ieee80211_frequency_to_channel(chan->center_freq) % 16 == 5;
}
#endif

static inline void
cfg80211_control_port_tx_status(struct wireless_dev *wdev, u64 cookie,
				const u8 *buf, size_t len, bool ack,
				gfp_t gfp)
{
}

static inline __le16
ieee80211_get_he_6ghz_capa(const struct ieee80211_supported_band *sband,
			   enum nl80211_iftype iftype)
{
	return 0;
}
void ieee80211_mgmt_frame_register(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   u16 frame_type, bool reg);

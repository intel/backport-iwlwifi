#define IEEE80211_CHAN_NO_UHR 0
#define NL80211_RRF_NO_UHR 0
#define ASSOC_REQ_DISABLE_UHR 0

struct ieee80211_sta_uhr_cap {
	bool has_uhr;
	struct ieee80211_uhr_cap_mac mac;
	struct ieee80211_uhr_cap_phy phy;
};

static inline const struct ieee80211_sta_uhr_cap *
ieee80211_get_uhr_iftype_cap(const struct ieee80211_supported_band *sband,
			     enum nl80211_iftype iftype)
{
	return NULL;
}


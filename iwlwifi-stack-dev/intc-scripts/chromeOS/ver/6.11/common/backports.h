
enum ieee80211_ap_reg_power {
	IEEE80211_REG_UNSET_AP,
	IEEE80211_REG_LPI_AP,
	IEEE80211_REG_SP_AP,
	IEEE80211_REG_VLP_AP,
};

/* upstream numbers */
#define NL80211_RRF_ALLOW_6GHZ_VLP_AP		BIT(24)
#define IEEE80211_CHAN_ALLOW_6GHZ_VLP_AP	BIT(25)

struct cfg80211_iface_usage {
	u32 types_mask;
};

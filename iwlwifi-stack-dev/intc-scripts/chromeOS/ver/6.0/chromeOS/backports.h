#ifdef CONFIG_THERMAL
static inline
int for_each_thermal_trip(struct thermal_zone_device *tz,
			  int (*cb)(struct thermal_trip *, void *),
			  void *data)
{
	return 0;
}
#endif /* CONFIG_THERMAL*/

static inline enum ieee80211_rate_flags
ieee80211_chanwidth_rate_flags(enum nl80211_chan_width width)
{
	switch (width) {
	case NL80211_CHAN_WIDTH_5:
		return IEEE80211_RATE_SUPPORTS_5MHZ;
	case NL80211_CHAN_WIDTH_10:
		return IEEE80211_RATE_SUPPORTS_10MHZ;
	default:
		break;
	}
	return 0;
}

#define WIPHY_FLAG_SUPPORTS_MLO 0

struct iwl7000_cfg80211_rx_assoc_resp {
	struct cfg80211_bss *bss;
	const u8 *buf;
	size_t len;
	const u8 *req_ies;
	size_t req_ies_len;
	int uapsd_queues;
	const u8 *ap_mld_addr;
	struct {
		u8 addr[ETH_ALEN];
		struct cfg80211_bss *bss;
		u16 status;
	} links[IEEE80211_MLD_MAX_NUM_LINKS];
};

static inline void
iwl7000_cfg80211_rx_assoc_resp(struct net_device *dev,
			       struct iwl7000_cfg80211_rx_assoc_resp *data)
{
	WARN_ON(data->ap_mld_addr);
	if (WARN_ON(!data->links[0].bss))
		return;

	cfg80211_rx_assoc_resp(dev, data->links[0].bss, data->buf, data->len,
			       data->uapsd_queues
#if LINUX_VERSION_IS_GEQ(5,1,0)
			       , data->req_ies, data->req_ies_len
#endif
			      );
}

#define cfg80211_rx_assoc_resp iwl7000_cfg80211_rx_assoc_resp

struct cfg80211_assoc_failure {
	const u8 *ap_mld_addr;
	struct cfg80211_bss *bss[IEEE80211_MLD_MAX_NUM_LINKS];
	bool timeout;
};

static inline void cfg80211_assoc_failure(struct net_device *dev,
					  struct cfg80211_assoc_failure *data)
{
	int i;

	WARN_ON(!data->bss[0]);
	WARN_ON(data->ap_mld_addr);

	for (i = 1; i < ARRAY_SIZE(data->bss); i++)
		WARN_ON(data->bss[i]);

	if (data->timeout)
		cfg80211_assoc_timeout(dev, data->bss[0]);
	else
		cfg80211_abandon_assoc(dev, data->bss[0]);
}

static inline const struct wiphy_iftype_ext_capab *
cfg80211_get_iftype_ext_capa(struct wiphy *wiphy, enum nl80211_iftype type)
{
	int i;

	for (i = 0; i < wiphy->num_iftype_ext_capab; i++) {
		if (wiphy->iftype_ext_capab[i].iftype == type)
			return &wiphy->iftype_ext_capab[i];
	}

	return NULL;
}

#ifndef for_each_valid_link
#define for_each_valid_link(dev, id) for (link_id = 0; link_id < 1; link_id++)
#endif

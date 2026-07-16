#define NL80211_RRF_ALLOW_20MHZ_ACTIVITY    BIT(25)

static inline int cfg80211_chandef_get_width(const struct cfg80211_chan_def *c)
{
	return nl80211_chan_width_to_mhz(c->width);
}

#ifndef MAC_ADDR_STR_LEN
#define MAC_ADDR_STR_LEN (3 * ETH_ALEN - 1)
#endif

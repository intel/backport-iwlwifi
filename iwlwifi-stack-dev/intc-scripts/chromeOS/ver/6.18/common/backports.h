#define IEEE80211_CHAN_S1G_NO_PRIMARY	BIT(27)
static inline bool
cfg80211_chandef_is_s1g(const struct cfg80211_chan_def *chandef)
{
	return chandef->chan->band == NL80211_BAND_S1GHZ;
}

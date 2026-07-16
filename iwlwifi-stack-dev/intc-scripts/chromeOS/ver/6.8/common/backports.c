int nl80211_chan_width_to_mhz(enum nl80211_chan_width chan_width)
{
	int mhz;

	switch (chan_width) {
	case NL80211_CHAN_WIDTH_1:
		mhz = 1;
		break;
	case NL80211_CHAN_WIDTH_2:
		mhz = 2;
		break;
	case NL80211_CHAN_WIDTH_4:
		mhz = 4;
		break;
	case NL80211_CHAN_WIDTH_8:
		mhz = 8;
		break;
	case NL80211_CHAN_WIDTH_16:
		mhz = 16;
		break;
	case NL80211_CHAN_WIDTH_5:
		mhz = 5;
		break;
	case NL80211_CHAN_WIDTH_10:
		mhz = 10;
		break;
	case NL80211_CHAN_WIDTH_20:
	case NL80211_CHAN_WIDTH_20_NOHT:
		mhz = 20;
		break;
	case NL80211_CHAN_WIDTH_40:
		mhz = 40;
		break;
	case NL80211_CHAN_WIDTH_80P80:
	case NL80211_CHAN_WIDTH_80:
		mhz = 80;
		break;
	case NL80211_CHAN_WIDTH_160:
		mhz = 160;
		break;
	case NL80211_CHAN_WIDTH_320:
		mhz = 320;
		break;
	default:
		WARN_ON_ONCE(1);
		return -1;
	}
	return mhz;
}
EXPORT_SYMBOL_GPL(nl80211_chan_width_to_mhz);

bool
ieee80211_uhb_power_type_valid(struct ieee80211_mgmt *mgmt, size_t len,
			       struct ieee80211_channel *channel)
{
	const struct element *tmp;
	struct ieee80211_he_operation *he_oper;
	bool ret = false;
	size_t ielen, min_hdr_len;
	u8 *variable = mgmt->u.probe_resp.variable;

	min_hdr_len = offsetof(struct ieee80211_mgmt,
			       u.probe_resp.variable);
	ielen = len - min_hdr_len;

	if (channel->band != NL80211_BAND_6GHZ)
		return true;

	tmp = cfg80211_find_ext_elem(WLAN_EID_EXT_HE_OPERATION,
				     variable, ielen);
	if (tmp && tmp->datalen >= sizeof(*he_oper) + 1) {
		const struct ieee80211_he_6ghz_oper *he_6ghz_oper;

		he_oper = (void *)&tmp->data[1];
		he_6ghz_oper = ieee80211_he_6ghz_oper(he_oper);
		if (!he_6ghz_oper)
			return false;

		switch (u8_get_bits(he_6ghz_oper->control,
				    IEEE80211_HE_6GHZ_OPER_CTRL_REG_INFO)) {
		case IEEE80211_6GHZ_CTRL_REG_LPI_AP:
		case IEEE80211_6GHZ_CTRL_REG_INDOOR_LPI_AP:
			return true;
		case IEEE80211_6GHZ_CTRL_REG_SP_AP:
		case IEEE80211_6GHZ_CTRL_REG_INDOOR_SP_AP:
			return !(channel->flags &
				 IEEE80211_CHAN_NO_6GHZ_AFC_CLIENT);
		case IEEE80211_6GHZ_CTRL_REG_VLP_AP:
			return !(channel->flags &
				 IEEE80211_CHAN_NO_6GHZ_VLP_CLIENT);
		default:
			return false;
		}
	}
	return false;
}

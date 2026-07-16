struct cfg80211_rx_info {
	int freq;
	int sig_dbm;
	bool have_link_id;
	u8 link_id;
	const u8 *buf;
	size_t len;
	u32 flags;
	u64 rx_tstamp;
	u64 ack_tstamp;
};

static inline bool cfg80211_rx_mgmt_ext(struct wireless_dev *wdev,
					struct cfg80211_rx_info *info)
{
	return cfg80211_rx_mgmt(wdev, KHZ_TO_MHZ(info->freq), info->sig_dbm,
				info->buf, info->len, info->flags);
}

/**
 * struct cfg80211_tx_status - TX status for management frame information
 *
 * @cookie: Cookie returned by cfg80211_ops::mgmt_tx()
 * @tx_tstamp: hardware TX timestamp in nanoseconds
 * @ack_tstamp: hardware ack RX timestamp in nanoseconds
 * @buf: Management frame (header + body)
 * @len: length of the frame data
 * @ack: Whether frame was acknowledged
 */
struct cfg80211_tx_status {
	u64 cookie;
	u64 tx_tstamp;
	u64 ack_tstamp;
	const u8 *buf;
	size_t len;
	bool ack;
};

static inline
void cfg80211_mgmt_tx_status_ext(struct wireless_dev *wdev,
				 struct cfg80211_tx_status *status, gfp_t gfp)
{
	cfg80211_mgmt_tx_status(wdev, status->cookie, status->buf, status->len,
				status->ack, gfp);
}

struct cfg80211_assoc_link {
	struct cfg80211_bss *bss;
	const u8 *elems;
	size_t elems_len;
	bool disabled;
	int error;
};

#define IEEE80211_CHAN_NO_HE 0
#define IEEE80211_CHAN_NO_EHT 0

#define NL80211_RRF_NO_HE 0

#define NL80211_CHAN_WIDTH_320 13

#define IEEE80211_EHT_PPE_THRES_MAX_LEN	32

struct ieee80211_eht_mcs_nss_supp {
	union {
		struct ieee80211_eht_mcs_nss_supp_20mhz_only only_20mhz;
		struct {
			struct ieee80211_eht_mcs_nss_supp_bw _80;
			struct ieee80211_eht_mcs_nss_supp_bw _160;
			struct ieee80211_eht_mcs_nss_supp_bw _320;
		} __packed bw;
	} __packed;
} __packed;

struct ieee80211_sta_eht_cap {
	bool has_eht;
	struct ieee80211_eht_cap_elem_fixed eht_cap_elem;
	struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp;
	u8 eht_ppe_thres[IEEE80211_EHT_PPE_THRES_MAX_LEN];
};

static inline const struct ieee80211_sta_eht_cap *
ieee80211_get_eht_iftype_cap(const struct ieee80211_supported_band *sband,
			     enum nl80211_iftype iftype)
{
	return NULL;
}

#define ieee80211_data_to_8023_exthdr iwl7000_ieee80211_data_to_8023_exthdr
int ieee80211_data_to_8023_exthdr(struct sk_buff *skb, struct ethhdr *ehdr,
				  const u8 *addr, enum nl80211_iftype iftype,
				  u8 data_offset, bool is_amsdu);

#define ieee80211_data_to_8023 iwl7000_ieee80211_data_to_8023
static inline int ieee80211_data_to_8023(struct sk_buff *skb, const u8 *addr,
					 enum nl80211_iftype iftype)
{
	return ieee80211_data_to_8023_exthdr(skb, NULL, addr, iftype, 0, false);
}

enum nl80211_eht_gi {
	NL80211_RATE_INFO_EHT_GI_0_8,
	NL80211_RATE_INFO_EHT_GI_1_6,
	NL80211_RATE_INFO_EHT_GI_3_2,
};

#define RATE_INFO_BW_320 (RATE_INFO_BW_HE_RU + 1)
#define NL80211_RRF_NO_320MHZ 0

/*
 * Same as SKB_DROP_REASON_NOT_SPECIFIED on some kernels,
 * but that's OK since we won't report these reasons to
 * the kernel anyway until 6.4, see kfree_skb_reason().
 */
#define SKB_NOT_DROPPED_YET	0

#ifdef CONFIG_THERMAL
#include <linux/thermal.h>

#define thermal_zone_device_priv LINUX_BACKPORT(thermal_zone_device_priv)
static inline void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return tzd->devdata;
}
#endif

#define ieee80211_is_valid_amsdu LINUX_BACKPORT(ieee80211_is_valid_amsdu)
static inline bool ieee80211_is_valid_amsdu(struct sk_buff *skb, u8 mesh_hdr)
{
	return mesh_hdr == 0;
}

static inline void
LINUX_BACKPORT(kfree_skb_reason)(struct sk_buff *skb, u32 reason)
{
#if LINUX_VERSION_IS_LESS(5,17,0)
	dev_kfree_skb(skb);
#else
	kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
#endif
}
#define kfree_skb_reason LINUX_BACKPORT(kfree_skb_reason)

static inline bool
iwl7000_cfg80211_rx_control_port(struct net_device *dev, struct sk_buff *skb,
				 bool unencrypted, int link_id)
{
	return cfg80211_rx_control_port(dev, skb, unencrypted);
}
#define cfg80211_rx_control_port iwl7000_cfg80211_rx_control_port

enum skb_drop_reason_subsys {
	SKB_DROP_REASON_SUBSYS_CORE,
	SKB_DROP_REASON_SUBSYS_MAC80211_UNUSABLE,
	SKB_DROP_REASON_SUBSYS_MAC80211_MONITOR,
	SKB_DROP_REASON_SUBSYS_NUM
};

struct drop_reason_list {
	const char * const *reasons;
	size_t n_reasons;
};

#define SKB_DROP_REASON_SUBSYS_SHIFT	16
#define SKB_DROP_REASON_SUBSYS_MASK	0xffff0000

static inline void
drop_reasons_register_subsys(enum skb_drop_reason_subsys subsys,
			     const struct drop_reason_list *list)
{}

static inline void
drop_reasons_unregister_subsys(enum skb_drop_reason_subsys subsys)
{}


static inline bool
backport_cfg80211_rx_spurious_frame(struct net_device *dev, const u8 *addr,
        int link_id, gfp_t gfp)
{
        return cfg80211_rx_spurious_frame(dev, addr, gfp);
}
#define cfg80211_rx_spurious_frame LINUX_BACKPORT(cfg80211_rx_spurious_frame)


static inline bool
backport_cfg80211_rx_unexpected_4addr_frame(struct net_device *dev, const u8 *addr,
        int link_id, gfp_t gfp)
{
        return cfg80211_rx_unexpected_4addr_frame(dev, addr, gfp);
}
#define cfg80211_rx_unexpected_4addr_frame LINUX_BACKPORT(cfg80211_rx_unexpected_4addr_frame)

#ifndef secs_to_jiffies
#define secs_to_jiffies(_secs) (unsigned long)((_secs) * HZ)
#endif

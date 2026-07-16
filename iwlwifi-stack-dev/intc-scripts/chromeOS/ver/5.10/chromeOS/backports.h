#define WIPHY_FLAG_SPLIT_SCAN_6GHZ 0
#define NL80211_SCAN_FLAG_COLOCATED_6GHZ 0

static inline enum nl80211_chan_width
ieee80211_s1g_channel_width(const struct ieee80211_channel *chan)
{
	return NL80211_CHAN_WIDTH_20_NOHT;
}

#define NL80211_BSS_CHAN_WIDTH_1	3
#define NL80211_BSS_CHAN_WIDTH_2	4

/**
 *      dev_fetch_sw_netstats - get per-cpu network device statistics
 *      @s: place to store stats
 *      @netstats: per-cpu network stats to read from
 *
 *      Read per-cpu network statistics and populate the related fields in @s.
 */
static inline
void dev_fetch_sw_netstats(struct rtnl_link_stats64 *s,
                           const struct pcpu_sw_netstats __percpu *netstats)
{
        int cpu;

        for_each_possible_cpu(cpu) {
                const struct pcpu_sw_netstats *stats;
                struct pcpu_sw_netstats tmp;
                unsigned int start;

                stats = per_cpu_ptr(netstats, cpu);
                do {
                        start = u64_stats_fetch_begin_irq(&stats->syncp);
                        tmp.rx_packets = stats->rx_packets;
                        tmp.rx_bytes   = stats->rx_bytes;
                        tmp.tx_packets = stats->tx_packets;
                        tmp.tx_bytes   = stats->tx_bytes;
                } while (u64_stats_fetch_retry_irq(&stats->syncp, start));

                s->rx_packets += tmp.rx_packets;
                s->rx_bytes   += tmp.rx_bytes;
                s->tx_packets += tmp.tx_packets;
                s->tx_bytes   += tmp.tx_bytes;
        }
}

static inline void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	tstats->rx_packets++;
	u64_stats_update_end(&tstats->syncp);
}

static inline u64 skb_get_kcov_handle(struct sk_buff *skb)
{
	return 0;
}

#define DECLARE_TRACEPOINT(tp) \
	extern struct tracepoint __tracepoint_##tp
#ifdef CONFIG_TRACEPOINTS
# define tracepoint_enabled(tp) \
	static_key_false(&(__tracepoint_##tp).key)
#else
# define tracepoint_enabled(tracepoint) false
#endif

#define ieee80211_he_obss_pd LINUX_BACKPORT(ieee80211_he_obss_pd)
struct ieee80211_he_obss_pd {
	bool enable;
	u8 sr_ctrl;
	u8 non_srg_max_offset;
	u8 min_offset;
	u8 max_offset;
	u8 bss_color_bitmap[8];
	u8 partial_bssid_bitmap[8];
};

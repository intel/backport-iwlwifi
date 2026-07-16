#ifndef CONFIG_LOCKDEP
/* upstream since 5.11 in this exact same way - calls compile away */
int lockdep_is_held(const void *);
#endif

static inline void dev_sw_netstats_tx_add(struct net_device *dev,
					  unsigned int packets,
					  unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->tx_bytes += len;
	tstats->tx_packets += packets;
	u64_stats_update_end(&tstats->syncp);
}

enum rfkill_hard_block_reasons {
	RFKILL_HARD_BLOCK_SIGNAL        = 1 << 0,
	RFKILL_HARD_BLOCK_NOT_OWNER     = 1 << 1,
};

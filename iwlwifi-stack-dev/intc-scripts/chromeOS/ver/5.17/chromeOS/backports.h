static inline void
cfg80211_assoc_comeback(struct net_device *netdev,
			struct cfg80211_bss *bss, u32 timeout)
{
}

#define rfkill_soft_blocked(__rfkill) rfkill_blocked(__rfkill)

static inline void __noreturn
kthread_complete_and_exit(struct completion *c, long ret)
{
	complete_and_exit(c, ret);
}

#define SKB_DROP_REASON_MAX	1

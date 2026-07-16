#define wiphy_dereference(w, r) rtnl_dereference(r)
#define regulatory_set_wiphy_regd_sync(w, r) regulatory_set_wiphy_regd_sync_rtnl(w, r)
#define lockdep_assert_wiphy(w) ASSERT_RTNL()
#define cfg80211_register_netdevice(n) register_netdevice(n)
#define cfg80211_unregister_netdevice(n) unregister_netdevice(n)
#define cfg80211_sched_scan_stopped_locked(w, r) cfg80211_sched_scan_stopped_rtnl(w, r)
#define ASSOC_REQ_DISABLE_HE BIT(4)
static inline void __iwl7000_cfg80211_unregister_wdev(struct wireless_dev *wdev)
{
	if (wdev->netdev)
		unregister_netdevice(wdev->netdev);
	else
		cfg80211_unregister_wdev(wdev);
}
#define cfg80211_unregister_wdev __iwl7000_cfg80211_unregister_wdev

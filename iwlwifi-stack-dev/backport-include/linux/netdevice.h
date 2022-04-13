#ifndef __BACKPORT_NETDEVICE_H
#define __BACKPORT_NETDEVICE_H
#include_next <linux/netdevice.h>
#include <linux/version.h>
#include <backport/magic.h>


#if LINUX_VERSION_IS_LESS(4,10,0)
static inline bool backport_napi_complete_done(struct napi_struct *n, int work_done)
{
	if (unlikely(test_bit(NAPI_STATE_NPSVC, &n->state)))
		return false;

	napi_complete_done(n, work_done);
	return true;
}

static inline bool backport_napi_complete(struct napi_struct *n)
{
	return backport_napi_complete_done(n, 0);
}
#define napi_complete_done LINUX_BACKPORT(napi_complete_done)
#define napi_complete LINUX_BACKPORT(napi_complete)
#endif /* < 4.10 */

#if LINUX_VERSION_IS_LESS(4,5,0)
#define netif_tx_napi_add LINUX_BACKPORT(netif_tx_napi_add)
/**
 *	netif_tx_napi_add - initialize a napi context
 *	@dev:  network device
 *	@napi: napi context
 *	@poll: polling function
 *	@weight: default weight
 *
 * This variant of netif_napi_add() should be used from drivers using NAPI
 * to exclusively poll a TX queue.
 * This will avoid we add it into napi_hash[], thus polluting this hash table.
 */
static inline void netif_tx_napi_add(struct net_device *dev,
				     struct napi_struct *napi,
				     int (*poll)(struct napi_struct *, int),
				     int weight)
{
	netif_napi_add(dev, napi, poll, weight);
}
#endif /* < 4.5 */

#ifndef NETIF_F_CSUM_MASK
#define NETIF_F_CSUM_MASK NETIF_F_ALL_CSUM
#endif

#if LINUX_VERSION_IS_LESS(4,7,0)
#define netif_trans_update LINUX_BACKPORT(netif_trans_update)
static inline void netif_trans_update(struct net_device *dev)
{
	dev->trans_start = jiffies;
}
#endif

#if LINUX_VERSION_IS_LESS(4,11,9)
#define netdev_set_priv_destructor(_dev, _destructor) \
	(_dev)->destructor = __ ## _destructor
#define netdev_set_def_destructor(_dev) \
	(_dev)->destructor = free_netdev
#else
#define netdev_set_priv_destructor(_dev, _destructor) \
	(_dev)->needs_free_netdev = true; \
	(_dev)->priv_destructor = (_destructor);
#define netdev_set_def_destructor(_dev) \
	(_dev)->needs_free_netdev = true;
#endif

#if LINUX_VERSION_IS_LESS(4,15,0)
static inline int _bp_netdev_upper_dev_link(struct net_device *dev,
					    struct net_device *upper_dev)
{
	return netdev_upper_dev_link(dev, upper_dev);
}
#define netdev_upper_dev_link3(dev, upper, extack) \
	netdev_upper_dev_link(dev, upper)
#define netdev_upper_dev_link2(dev, upper) \
	netdev_upper_dev_link(dev, upper)
#define netdev_upper_dev_link(...) \
	macro_dispatcher(netdev_upper_dev_link, __VA_ARGS__)(__VA_ARGS__)
#endif

#if LINUX_VERSION_IS_LESS(4,19,0)
static inline void netif_receive_skb_list(struct sk_buff_head *head)
{
	struct sk_buff *skb, *next;

	skb_queue_walk_safe(head, skb, next) {
		__skb_unlink(skb, head);
		netif_receive_skb(skb);
	}
}
#endif

#if LINUX_VERSION_IS_LESS(5,0,0)
static inline int backport_dev_open(struct net_device *dev, struct netlink_ext_ack *extack)
{
	return dev_open(dev);
}
#define dev_open LINUX_BACKPORT(dev_open)
#endif

#if LINUX_VERSION_IS_LESS(5,10,0)
#define dev_fetch_sw_netstats LINUX_BACKPORT(dev_fetch_sw_netstats)
void dev_fetch_sw_netstats(struct rtnl_link_stats64 *s,
			   const struct pcpu_sw_netstats __percpu *netstats);

#define netif_rx_any_context LINUX_BACKPORT(netif_rx_any_context)
int netif_rx_any_context(struct sk_buff *skb);

static inline void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	tstats->rx_packets++;
	u64_stats_update_end(&tstats->syncp);
}

#endif /* < 5.10 */

#if LINUX_VERSION_IS_LESS(5,11,0)
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
#endif /* < 5.10 */

#if LINUX_VERSION_IS_LESS(5,10,0)
#define dev_sw_netstats_rx_add LINUX_BACKPORT(dev_sw_netstats_rx_add)
static inline void dev_sw_netstats_rx_add(struct net_device *dev, unsigned int len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_bytes += len;
	tstats->rx_packets++;
	u64_stats_update_end(&tstats->syncp);
}
#endif /* < 5.10 */

#if LINUX_VERSION_IS_LESS(5,11,0)
#define dev_sw_netstats_tx_add LINUX_BACKPORT(dev_sw_netstats_tx_add)
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
#endif /* < 5.11 */

#if LINUX_VERSION_IS_LESS(5,11,0)
#define dev_get_tstats64 LINUX_BACKPORT(dev_get_tstats64)
void dev_get_tstats64(struct net_device *dev, struct rtnl_link_stats64 *s);
#endif /* < 5.11 */

#if LINUX_VERSION_IS_LESS(4,11,0)
struct rtnl_link_stats64 *
bp_dev_get_tstats64(struct net_device *dev, struct rtnl_link_stats64 *s);
#endif /* < 4.11 */

#if LINUX_VERSION_IS_LESS(5,15,0)
static inline void backport_dev_put(struct net_device *dev)
{
	if (dev)
		dev_put(dev);
}
#define dev_put LINUX_BACKPORT(dev_put)

static inline void backport_dev_hold(struct net_device *dev)
{
	if (dev)
		dev_hold(dev);
}
#define dev_hold LINUX_BACKPORT(dev_hold)
#endif /* < 5.15 */

#endif /* __BACKPORT_NETDEVICE_H */

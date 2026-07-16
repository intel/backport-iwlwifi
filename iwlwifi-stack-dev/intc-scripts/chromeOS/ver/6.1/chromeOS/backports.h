#define ASSOC_REQ_DISABLE_EHT BIT(5)
#define NL80211_EXT_FEATURE_POWERED_ADDR_CHANGE -1

static inline u16 get_random_u16(void)
{
	return get_random_int() & 0xffff;
}

static inline u32 get_random_u32_below(u32 ceil)
{
	return prandom_u32_max(ceil);
}

static inline u32 get_random_u32_inclusive(u32 floor, u32 ceil)
{
	BUILD_BUG_ON_MSG(__builtin_constant_p(floor) && __builtin_constant_p(ceil) &&
			 (floor > ceil || ceil - floor == U32_MAX),
			 "get_random_u32_inclusive() must take floor <= ceil");
	return floor + get_random_u32_below(ceil - floor + 1);
}

struct cfg80211_set_hw_timestamp {
	const u8 *macaddr;
	bool enable;
};

static inline void backport_netif_napi_add(struct net_device *dev,
					   struct napi_struct *napi,
					   int (*poll)(struct napi_struct *, int))
{
	netif_napi_add(dev, napi, poll, NAPI_POLL_WEIGHT);
}
#define netif_napi_add LINUX_BACKPORT(netif_napi_add)

#define ieee80211_amsdu_to_8023s(skb, list, addr, type, headroom, check_sa, check_da, mesh) \
	ieee80211_amsdu_to_8023s(skb, list, addr, type, headroom, check_sa, check_da)

#include <linux/cleanup.h>
DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))

DEFINE_LOCK_GUARD_0(rcu,
	do {
		rcu_read_lock();
		/*
		 * sparse doesn't call the cleanup function,
		 * so just release immediately and don't track
		 * the context. We don't need to anyway, since
		 * the whole point of the guard is to not need
		 * the explicit unlock.
		 */
		__release(RCU);
	} while (0),
	rcu_read_unlock())

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#if __has_builtin(__builtin_dynamic_object_size)
#define __struct_size(p)	__builtin_dynamic_object_size(p, 0)
#define __member_size(p)	__builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)
#endif

#ifndef __IWL_CHROME
#define __IWL_CHROME
/* This file is pre-included from the Makefile (cc command line)
 *
 * ChromeOS backport definitions
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018-2022 Intel Corporation
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/vmalloc.h>

/* get the CPTCFG_* preprocessor symbols */
#include <hdrs/config.h>

#include <hdrs/mac80211-exp.h>

#define LINUX_VERSION_IS_LESS(x1,x2,x3) (LINUX_VERSION_CODE < KERNEL_VERSION(x1,x2,x3))
#define LINUX_VERSION_IS_GEQ(x1,x2,x3)  (LINUX_VERSION_CODE >= KERNEL_VERSION(x1,x2,x3))
#define LINUX_VERSION_IN_RANGE(x1,x2,x3, y1,y2,y3) \
        (LINUX_VERSION_IS_GEQ(x1,x2,x3) && LINUX_VERSION_IS_LESS(y1,y2,y3))
#define LINUX_BACKPORT(sym) backport_ ## sym

/* this must be before including rhashtable.h */
#if LINUX_VERSION_IS_LESS(4,15,0)
#ifndef CONFIG_LOCKDEP
struct lockdep_map { };
#endif /* CONFIG_LOCKDEP */
#endif /* LINUX_VERSION_IS_LESS(4,15,0) */

/* include rhashtable this way to get our copy if another exists */
#include <linux/list_nulls.h>
#include "linux/rhashtable.h"

#include <net/genetlink.h>
#include <linux/crypto.h>
#include <linux/moduleparam.h>
#include <linux/debugfs.h>
#include <linux/hrtimer.h>
#include <crypto/algapi.h>
#include <linux/pci.h>
#include <linux/if_vlan.h>
#include <linux/overflow.h>
#include "net/fq.h"

#if LINUX_VERSION_IS_LESS(3,20,0)
#define get_net_ns_by_fd LINUX_BACKPORT(get_net_ns_by_fd)
static inline struct net *get_net_ns_by_fd(int fd)
{
	return ERR_PTR(-EINVAL);
}
#endif

#ifndef DECLARE_FLEX_ARRAY
/**
 * __DECLARE_FLEX_ARRAY() - Declare a flexible array usable in a union
 *
 * @TYPE: The type of each flexible array element
 * @NAME: The name of the flexible array member
 *
 * In order to have a flexible array member in a union or alone in a
 * struct, it needs to be wrapped in an anonymous struct with at least 1
 * named member, but that member can be empty.
+ */
#define __DECLARE_FLEX_ARRAY(TYPE, NAME)       \
	struct {			       \
		struct { } __empty_ ## NAME;   \
		TYPE NAME[];		       \
	}

/**
 * DECLARE_FLEX_ARRAY() - Declare a flexible array usable in a union
 *
 * @TYPE: The type of each flexible array element
 * @NAME: The name of the flexible array member
 *
 * In order to have a flexible array member in a union or alone in a
 * struct, it needs to be wrapped in an anonymous struct with at least 1
 * named member, but that member can be empty.
 */
#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)
#endif

/*
 * Need to include these here, otherwise we get the regular kernel ones
 * pre-including them makes it work, even though later the kernel ones
 * are included again, but they (hopefully) have the same include guard
 * ifdef/define so the second time around nothing happens
 *
 * We still keep them in the correct directory so if they don't exist in
 * the kernel (e.g. bitfield.h won't) the preprocessor can find them.
 */
#include <hdrs/linux/bitfield.h>
#include <hdrs/linux/ieee80211.h>
#include <hdrs/linux/average.h>
#include <hdrs/net/ieee80211_radiotap.h>
#define IEEE80211RADIOTAP_H 1 /* older kernels used this include protection */

/* mac80211 & backport - order matters, need this inbetween */
#include <hdrs/mac80211-bp.h>

#include <hdrs/net/codel.h>
#include <hdrs/net/mac80211.h>

/* artifacts of backports - never in upstream */
#define genl_info_snd_portid(__genl_info) (__genl_info->snd_portid)
#define NETLINK_CB_PORTID(__skb) NETLINK_CB(cb->skb).portid
#define netlink_notify_portid(__notify) __notify->portid
#define __genl_const const

static inline struct netlink_ext_ack *genl_info_extack(struct genl_info *info)
{
#if LINUX_VERSION_IS_GEQ(4,12,0)
	return info->extack;
#else
	return NULL;
#endif
}

#if LINUX_VERSION_IS_LESS(5,3,0)
#define ktime_get_boottime_ns ktime_get_boot_ns
#define ktime_get_coarse_boottime_ns ktime_get_boot_ns
#endif

#ifndef NETIF_F_CSUM_MASK
#define NETIF_F_CSUM_MASK (NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
int __must_check kstrtobool(const char *s, bool *res);
int __must_check kstrtobool_from_user(const char __user *s, size_t count, bool *res);
#endif /* < 4.6 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
#define nla_put_s64 iwl7000_nla_put_s64
static inline int nla_put_s64(struct sk_buff *skb, int attrtype, s64 value,
			      int padattr)
{
	return nla_put_u64(skb, attrtype, value);
}
void dev_coredumpsg(struct device *dev, struct scatterlist *table,
		    size_t datalen, gfp_t gfp);
#endif /* < 4.7 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
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

/* on earlier kernels, genl_unregister_family() modifies the struct */
#define __genl_ro_after_init
#else
#define __genl_ro_after_init __ro_after_init
#endif

#ifndef __BUILD_BUG_ON_NOT_POWER_OF_2
#define __BUILD_BUG_ON_NOT_POWER_OF_2(...)
#endif

#define ATTRIBUTE_GROUPS_BACKPORT(_name) \
static struct BP_ATTR_GRP_STRUCT _name##_dev_attrs[ARRAY_SIZE(_name##_attrs)];\
static void init_##_name##_attrs(void)				\
{									\
	int i;								\
	for (i = 0; _name##_attrs[i]; i++)				\
		_name##_dev_attrs[i] =				\
			*container_of(_name##_attrs[i],		\
				      struct BP_ATTR_GRP_STRUCT,	\
				      attr);				\
}

#ifndef __ATTRIBUTE_GROUPS
#define __ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group *_name##_groups[] = {	\
	&_name##_group,						\
	NULL,							\
}
#endif /* __ATTRIBUTE_GROUPS */

#undef ATTRIBUTE_GROUPS
#define ATTRIBUTE_GROUPS(_name)					\
static const struct attribute_group _name##_group = {		\
	.attrs = _name##_attrs,					\
};								\
static inline void init_##_name##_attrs(void) {}		\
__ATTRIBUTE_GROUPS(_name)

#if LINUX_VERSION_IS_LESS(4,10,0)
static inline void *nla_memdup(const struct nlattr *src, gfp_t gfp)
{
	return kmemdup(nla_data(src), nla_len(src), gfp);
}
#endif

#if LINUX_VERSION_IS_LESS(4,15,0)
static inline
void backport_genl_dump_check_consistent(struct netlink_callback *cb,
					 void *user_hdr)
{
	struct genl_family dummy_family = {
		.hdrsize = 0,
	};

	genl_dump_check_consistent(cb, user_hdr, &dummy_family);
}
#define genl_dump_check_consistent LINUX_BACKPORT(genl_dump_check_consistent)
#endif /* LINUX_VERSION_IS_LESS(4,15,0) */

#if LINUX_VERSION_IS_LESS(4,10,0)
/**
 * genl_family_attrbuf - return family's attrbuf
 * @family: the family
 *
 * Return the family's attrbuf, while validating that it's
 * actually valid to access it.
 *
 * You cannot use this function with a family that has parallel_ops
 * and you can only use it within (pre/post) doit/dumpit callbacks.
 */
#define genl_family_attrbuf LINUX_BACKPORT(genl_family_attrbuf)
static inline struct nlattr **genl_family_attrbuf(struct genl_family *family)
{
	WARN_ON(family->parallel_ops);

	return family->attrbuf;
}

#define __genl_ro_after_init
#else
#define __genl_ro_after_init __ro_after_init
#endif

#ifndef GENL_UNS_ADMIN_PERM
#define GENL_UNS_ADMIN_PERM GENL_ADMIN_PERM
#endif

#if LINUX_VERSION_IS_LESS(4, 1, 0)
#define dev_of_node LINUX_BACKPORT(dev_of_node)
static inline struct device_node *dev_of_node(struct device *dev)
{
#ifndef CONFIG_OF
	return NULL;
#else
	return dev->of_node;
#endif
}
#endif /* LINUX_VERSION_IS_LESS(4, 1, 0) */

#if LINUX_VERSION_IS_LESS(4,12,0)
#include "magic.h"

static inline int nla_validate5(const struct nlattr *head,
				int len, int maxtype,
				const struct nla_policy *policy,
				struct netlink_ext_ack *extack)
{
	return nla_validate(head, len, maxtype, policy);
}
#define nla_validate4 nla_validate
#define nla_validate(...) \
	macro_dispatcher(nla_validate, __VA_ARGS__)(__VA_ARGS__)

static inline int nla_parse6(struct nlattr **tb, int maxtype,
			     const struct nlattr *head,
			     int len, const struct nla_policy *policy,
			     struct netlink_ext_ack *extack)
{
	return nla_parse(tb, maxtype, head, len, policy);
}
#define nla_parse5(...) nla_parse(__VA_ARGS__)
#define nla_parse(...) \
	macro_dispatcher(nla_parse, __VA_ARGS__)(__VA_ARGS__)

static inline int nlmsg_parse6(const struct nlmsghdr *nlh, int hdrlen,
			       struct nlattr *tb[], int maxtype,
			       const struct nla_policy *policy,
			       struct netlink_ext_ack *extack)
{
	return nlmsg_parse(nlh, hdrlen, tb, maxtype, policy);
}
#define nlmsg_parse5 nlmsg_parse
#define nlmsg_parse(...) \
	macro_dispatcher(nlmsg_parse, __VA_ARGS__)(__VA_ARGS__)

static inline int nlmsg_validate5(const struct nlmsghdr *nlh,
				  int hdrlen, int maxtype,
				  const struct nla_policy *policy,
				  struct netlink_ext_ack *extack)
{
	return nlmsg_validate(nlh, hdrlen, maxtype, policy);
}
#define nlmsg_validate4 nlmsg_validate
#define nlmsg_validate(...) \
	macro_dispatcher(nlmsg_validate, __VA_ARGS__)(__VA_ARGS__)

static inline int nla_parse_nested5(struct nlattr *tb[], int maxtype,
				    const struct nlattr *nla,
				    const struct nla_policy *policy,
				    struct netlink_ext_ack *extack)
{
	return nla_parse_nested(tb, maxtype, nla, policy);
}
#define nla_parse_nested4 nla_parse_nested
#define nla_parse_nested(...) \
	macro_dispatcher(nla_parse_nested, __VA_ARGS__)(__VA_ARGS__)

static inline int nla_validate_nested4(const struct nlattr *start, int maxtype,
				       const struct nla_policy *policy,
				       struct netlink_ext_ack *extack)
{
	return nla_validate_nested(start, maxtype, policy);
}
#define nla_validate_nested3 nla_validate_nested
#define nla_validate_nested(...) \
	macro_dispatcher(nla_validate_nested, __VA_ARGS__)(__VA_ARGS__)

#define kvmalloc LINUX_BACKPORT(kvmalloc)
static inline void *kvmalloc(size_t size, gfp_t flags)
{
	gfp_t kmalloc_flags = flags;
	void *ret;

	if ((flags & GFP_KERNEL) != GFP_KERNEL)
		return kmalloc(size, flags);

	if (size > PAGE_SIZE)
		kmalloc_flags |= __GFP_NOWARN | __GFP_NORETRY;

	ret = kmalloc(size, flags);
	if (ret || size < PAGE_SIZE)
		return ret;

	return vmalloc(size);
}

#define kvmalloc_array LINUX_BACKPORT(kvmalloc_array)
static inline void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	return kvmalloc(bytes, flags);
}

#define kvzalloc LINUX_BACKPORT(kvzalloc)
static inline void *kvzalloc(size_t size, gfp_t flags)
{
	return kvmalloc(size, flags | __GFP_ZERO);
}

#endif /* LINUX_VERSION_IS_LESS(4,12,0) */

#if LINUX_VERSION_IS_LESS(4,14,0)
static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc_array(n, size, flags | __GFP_ZERO);
}
#endif /* LINUX_VERSION_IS_LESS(4,14,0) */

/* avoid conflicts with other headers */
#ifdef is_signed_type
#undef is_signed_type
#endif

#ifndef offsetofend
/**
 * offsetofend(TYPE, MEMBER)
 *
 * @TYPE: The type of the structure
 * @MEMBER: The member within the structure to get the end offset of
 */
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof(((TYPE *)0)->MEMBER))
#endif


int __alloc_bucket_spinlocks(spinlock_t **locks, unsigned int *lock_mask,
			     size_t max_size, unsigned int cpu_mult,
			     gfp_t gfp, const char *name,
			     struct lock_class_key *key);

#define alloc_bucket_spinlocks(locks, lock_mask, max_size, cpu_mult, gfp)    \
	({								     \
		static struct lock_class_key key;			     \
		int ret;						     \
									     \
		ret = __alloc_bucket_spinlocks(locks, lock_mask, max_size,   \
					       cpu_mult, gfp, #locks, &key); \
		ret;							\
	})
void free_bucket_spinlocks(spinlock_t *locks);

#if LINUX_VERSION_IS_LESS(4,12,0)
#define GENL_SET_ERR_MSG(info, msg) do { } while (0)

static inline int genl_err_attr(struct genl_info *info, int err,
				struct nlattr *attr)
{
#if LINUX_VERSION_IS_GEQ(4,12,0)
	info->extack->bad_attr = attr;
#endif

	return err;
}
#endif

#if LINUX_VERSION_IS_LESS(4,19,0)
#ifndef atomic_fetch_add_unless
static inline int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{
		return __atomic_add_unless(v, a, u);
}
#endif
#endif /* LINUX_VERSION_IS_LESS(4,19,0) */

#if LINUX_VERSION_IS_LESS(4,20,0)
static inline void rcu_head_init(struct rcu_head *rhp)
{
	rhp->func = (void *)~0L;
}

static inline bool
rcu_head_after_call_rcu(struct rcu_head *rhp, void *f)
{
	if (READ_ONCE(rhp->func) == f)
		return true;
	WARN_ON_ONCE(READ_ONCE(rhp->func) != (void *)~0L);
	return false;
}
#endif /* LINUX_VERSION_IS_LESS(4,20,0) */

#if LINUX_VERSION_IS_LESS(4,14,0)
#define skb_mark_not_on_list iwl7000_skb_mark_not_on_list
static inline void skb_mark_not_on_list(struct sk_buff *skb)
{
	skb->next = NULL;
}
#endif /* LINUX_VERSION_IS_LESS(4,14,0) */

#if LINUX_VERSION_IS_LESS(5,4,0)
#include <linux/pci-aspm.h>
#define EXPORT_SYMBOL_NS_GPL(sym, ns) EXPORT_SYMBOL_GPL(sym)
#define MODULE_IMPORT_NS(ns)
#endif

#if LINUX_VERSION_IS_LESS(5,5,0)
#include <linux/debugfs.h>

#define debugfs_create_xul iwl7000_debugfs_create_xul
static inline void debugfs_create_xul(const char *name, umode_t mode,
				      struct dentry *parent,
				      unsigned long *value)
{
	if (sizeof(*value) == sizeof(u32))
		debugfs_create_x32(name, mode, parent, (u32 *)value);
	else
		debugfs_create_x64(name, mode, parent, (u64 *)value);
}
#endif

#ifndef skb_list_walk_safe
#define skb_list_walk_safe(first, skb, next_skb)				\
	for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb);	\
	     (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)
#endif

#if LINUX_VERSION_IS_LESS(4,13,0) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,6)
#include <linux/acpi.h>
#include <linux/uuid.h>

#define guid_t uuid_le
#define uuid_t uuid_be

static inline void guid_gen(guid_t *u)
{
	return uuid_le_gen(u);
}

static inline void uuid_gen(uuid_t *u)
{
	return uuid_be_gen(u);
}

static inline void guid_copy(guid_t *dst, const guid_t *src)
{
	memcpy(dst, src, sizeof(guid_t));
}

#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)	\
	UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)

static inline union acpi_object *
LINUX_BACKPORT(acpi_evaluate_dsm)(acpi_handle handle, const guid_t *guid,
				  u64 rev, u64 func, union acpi_object *args)
{
	return acpi_evaluate_dsm(handle, guid->b, rev, func, args);
}

#define acpi_evaluate_dsm LINUX_BACKPORT(acpi_evaluate_dsm)
#endif

#if LINUX_VERSION_IS_LESS(4,18,0)
#define firmware_request_nowarn(fw, name, device) request_firmware(fw, name, device)
#endif

#endif /* __IWL_CHROME */

#if LINUX_VERSION_IS_LESS(5,4,0)

/**
 * list_for_each_entry_rcu	-	iterate over rcu list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 * @cond...:	optional lockdep expression if called from non-RCU protection.
 *
 * This list-traversal primitive may safely run concurrently with
 * the _rcu list-mutation primitives such as list_add_rcu()
 * as long as the traversal is guarded by rcu_read_lock().
 */
#undef list_for_each_entry_rcu
#define list_for_each_entry_rcu(pos, head, member, cond...)		\
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#endif /* < 5.4 */

#if LINUX_VERSION_IS_LESS(5,7,0)
#define efi_rt_services_supported(...) efi_enabled(EFI_RUNTIME_SERVICES)
#endif

#if LINUX_VERSION_IS_LESS(5,11,0)

enum rfkill_hard_block_reasons {
	RFKILL_HARD_BLOCK_SIGNAL        = 1 << 0,
	RFKILL_HARD_BLOCK_NOT_OWNER     = 1 << 1,
};
#endif /* < v5.11 */

#if LINUX_VERSION_IS_LESS(5,13,0)
/* This will get enum rfkill_hard_block_reasons used below */
#include <uapi/linux/rfkill.h>

static inline void
wiphy_rfkill_set_hw_state_reason(struct wiphy *wiphy, bool blocked,
				 enum rfkill_hard_block_reasons reason)
{
	wiphy_rfkill_set_hw_state(wiphy, blocked);
}

#endif /* < v5.13 */

#if LINUX_VERSION_IS_LESS(5,14,0)
/* make this code disappear, rfkill moved from rdev to wiphy */
#define rfkill_blocked(__rkfill) false
#endif /* < v5.14 */

#if LINUX_VERSION_IS_LESS(5,17,0)
#define rfkill_soft_blocked(__rfkill) rfkill_blocked(__rfkill)

static inline void __noreturn
kthread_complete_and_exit(struct completion *c, long ret)
{
	complete_and_exit(c, ret);
}
#endif /* <v5.17 */

#ifndef __BP_KUNIT_SKBUFF_H
#define __BP_KUNIT_SKBUFF_H
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,9,0)
#include <kunit/resource.h>
#include <linux/skbuff.h>

/**
 * kunit_zalloc_skb() - Allocate and initialize a resource managed skb.
 * @test: The test case to which the skb belongs
 * @len: size to allocate
 *
 * Allocate a new struct sk_buff with GFP_KERNEL, zero fill the give length
 * and add it as a resource to the kunit test for automatic cleanup.
 *
 * Returns: newly allocated SKB, or %NULL on error
 */
static inline struct sk_buff *kunit_zalloc_skb(struct kunit *test, int len,
					       gfp_t gfp)
{
	struct sk_buff *res = alloc_skb(len, GFP_KERNEL);

	if (!res || skb_pad(res, len))
		return NULL;

	if (kunit_add_action_or_reset(test, (kunit_action_t*)kfree_skb, res))
		return NULL;

	return res;
}

/**
 * kunit_kfree_skb() - Like kfree_skb except for allocations managed by KUnit.
 * @test: The test case to which the resource belongs.
 * @skb: The SKB to free.
 */
static inline void kunit_kfree_skb(struct kunit *test, struct sk_buff *skb)
{
	if (!skb)
		return;

	kunit_release_action(test, (kunit_action_t *)kfree_skb, (void *)skb);
}
#else /* LINUX_VERSION_IS_LESS(6,6,0) */
#include_next <kunit/skbuff.h>
#endif /* LINUX_VERSION_IS_LESS(6,6,0) */

#endif /* __BP_KUNIT_SKBUFF_H */

#ifndef __BACKPORT_MM_H
#define __BACKPORT_MM_H
#include_next <linux/mm.h>
#include <linux/overflow.h>

#if LINUX_VERSION_IS_LESS(4,18,0)
#define kvcalloc LINUX_BACKPORT(kvcalloc)
static inline void *kvcalloc(size_t n, size_t size, gfp_t flags)
{
	return kvmalloc_array(n, size, flags | __GFP_ZERO);
}
#endif /* < 4.18 */
#if LINUX_VERSION_IS_LESS(6,3,0)

#define kvmemdup LINUX_BACKPORT(kvmemdup)
static inline void *kvmemdup(const void *src, size_t len, gfp_t gfp)
{
	void *p;

	p = kvmalloc(len, gfp);
	if (p)
		memcpy(p, src, len);
	return p;
}
#endif

#endif /* __BACKPORT_MM_H */

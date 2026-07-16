#ifndef __BACKPORT_LINUX_STRING_H
#define __BACKPORT_LINUX_STRING_H
#include_next <linux/string.h>
#include <linux/version.h>

#ifndef memset_after
#define memset_after(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetofend(typeof(*(obj)), member), __val,	\
	       sizeof(*(obj)) - offsetofend(typeof(*(obj)), member));	\
})
#endif

#ifndef memset_startat
#define memset_startat(obj, v, member)					\
({									\
	u8 *__ptr = (u8 *)(obj);					\
	typeof(v) __val = (v);						\
	memset(__ptr + offsetof(typeof(*(obj)), member), __val,		\
	       sizeof(*(obj)) - offsetof(typeof(*(obj)), member));	\
})
#endif

#if LINUX_VERSION_IS_LESS(5,2,0)
#define strscpy_pad LINUX_BACKPORT(strscpy_pad)
ssize_t strscpy_pad(char *dest, const char *src, size_t count);
#endif

#if LINUX_VERSION_IS_LESS(6,10,0)
#include <linux/overflow.h>
#define kmemdup_array LINUX_BACKPORT(kmemdup_array)
static inline void *
kmemdup_array(const void *src, size_t count, size_t element_size, gfp_t gfp)
{
	return kmemdup(src, size_mul(element_size, count), gfp);
}
#endif

#endif /* __BACKPORT_LINUX_STRING_H */

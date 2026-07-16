#ifndef __BACKPORT_LINUX_KTIME_H
#define __BACKPORT_LINUX_KTIME_H
#include <linux/version.h>
#include_next <linux/ktime.h>

#if LINUX_VERSION_IS_LESS(6,14,0)
static inline ktime_t us_to_ktime(u64 us)
{
	return us * NSEC_PER_USEC;
}
#endif /* < 6.14 */

#endif /* __BACKPORT_LINUX_KTIME_H */

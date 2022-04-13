#ifndef __BACKPORT_TIMEKEEPING_H
#define __BACKPORT_TIMEKEEPING_H
#include <linux/version.h>
#include <linux/types.h>

#include_next <linux/timekeeping.h>

#if LINUX_VERSION_IS_LESS(5,3,0)
#define ktime_get_boottime_ns LINUX_BACKPORT(ktime_get_boottime_ns)
static inline u64 ktime_get_boottime_ns(void)
{
	return ktime_get_boot_ns();
}
#endif /* < 5.3 */

#if LINUX_VERSION_IS_GEQ(5,3,0)
/*
 * In v5.3, this function was renamed, so rename it here for v5.3+.
 * When we merge v5.3 back from upstream, the opposite should be done
 * (i.e. we will have _boottime_ and need to rename to _boot_ in <
 * v5.3 instead).
*/
#define ktime_get_boot_ns ktime_get_boottime_ns
#endif /* > 5.3.0 */

#if LINUX_VERSION_IS_LESS(4,18,0)
extern time64_t ktime_get_boottime_seconds(void);
#endif /* < 4.18 */

#if LINUX_VERSION_IS_LESS(4,18,0)
#define ktime_get_raw_ts64 LINUX_BACKPORT(ktime_get_raw_ts64)
static inline void ktime_get_raw_ts64(struct timespec64 *ts)
{
	return getrawmonotonic64(ts);
}
#endif

#endif /* __BACKPORT_TIMEKEEPING_H */

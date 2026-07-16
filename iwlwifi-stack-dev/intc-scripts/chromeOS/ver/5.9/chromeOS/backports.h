#include <linux/math64.h>

#define kfree_sensitive(p) kzfree(p)

#include <linux/thermal.h>
#ifdef CONFIG_THERMAL
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return 0; }
#else /* CONFIG_THERMAL */
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return -ENODEV; }
#endif /* CONFIG_THERMAL */

#define NL80211_BAND_S1GHZ 4
#define NL80211_CHAN_WIDTH_1 8
#define NL80211_CHAN_WIDTH_2 9
#define NL80211_CHAN_WIDTH_4 10
#define NL80211_CHAN_WIDTH_8 11
#define NL80211_CHAN_WIDTH_16 12

u64 mul_u64_u64_div_u64(u64 a, u64 b, u64 c);

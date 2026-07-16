#ifndef __BACKPORT_LINUX_THERMAL_H
#define __BACKPORT_LINUX_THERMAL_H
#include_next <linux/thermal.h>
#include <linux/version.h>

#ifdef CONFIG_THERMAL
#if LINUX_VERSION_IS_LESS(5,9,0)
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return 0; }
#endif /* < 5.9.0 */

#if LINUX_VERSION_IS_LESS(6,9,0)
struct backport_thermal_trip {
	int temperature;
	int hysteresis;
	int threshold;
	enum thermal_trip_type type;
	u8 flags;
	void *priv;
};
#define thermal_trip backport_thermal_trip

#define THERMAL_TRIP_FLAG_RW_TEMP       BIT(0)

#define thermal_zone_device_register_with_trips LINUX_BACKPORT(thermal_zone_device_register_with_trips)
struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					struct thermal_trip *trips,
					int num_trips, void *devdata,
					struct thermal_zone_device_ops *ops,
					struct thermal_zone_params *tzp,
					int passive_delay,
					int polling_delay);
#endif /* <6,9,0 */

#if LINUX_VERSION_IS_LESS(6,9,0) && LINUX_VERSION_IS_GEQ(6,0,0)
#define for_each_thermal_trip LINUX_BACKPORT(for_each_thermal_trip)
static inline
int for_each_thermal_trip(struct thermal_zone_device *tz,
			  int (*cb)(struct thermal_trip *, void *),
			  void *data)
{
	struct thermal_trip *trip;
	struct thermal_trip *trips = (void *)tz->trips;
	int ret;

	for (trip = trips; trip - trips < tz->num_trips; trip++) {
		ret = cb(trip, data);
		if (ret)
			return ret;
	}

	return 0;
}
#endif /* < 6,9,0 && >= 6,0,0 */

/* for < 6,0,0 the trips are invalid anyway*/
#if LINUX_VERSION_IS_LESS(6,0,0)
static inline
int for_each_thermal_trip(struct thermal_zone_device *tz,
			  int (*cb)(struct thermal_trip *, void *),
			  void *data)
{
	return 0;
}
#endif

#if LINUX_VERSION_IS_LESS(6,4,0)
#define thermal_zone_device_priv LINUX_BACKPORT(thermal_zone_device_priv)
static inline void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return tzd->devdata;
}
#endif /* < 6.4.0 */
#else /* CONFIG_THERMAL */
#if LINUX_VERSION_IS_LESS(5,9,0)
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return -ENODEV; }
#endif /* < 5.9.0 */

#if LINUX_VERSION_IS_LESS(6,9,0)
#define thermal_zone_device_register_with_trips LINUX_BACKPORT(thermal_zone_device_register_with_trips)
static inline struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					struct thermal_trip *trips,
					int num_trips, void *devdata,
					struct thermal_zone_device_ops *ops,
					struct thermal_zone_params *tzp,
					int passive_delay,
					int polling_delay)
{
	return NULL;
}
#endif

#if LINUX_VERSION_IS_LESS(6,4,0)
#define thermal_zone_device_priv LINUX_BACKPORT(thermal_zone_device_priv)
static inline void *thermal_zone_device_priv(struct thermal_zone_device *tzd)
{
	return NULL;
}
#endif /* < 6.4.0 */
#endif /* CONFIG_THERMAL */

#if LINUX_VERSION_IS_LESS(5,9,0)
#define thermal_zone_device_enable LINUX_BACKPORT(thermal_zone_device_enable)
static inline int thermal_zone_device_enable(struct thermal_zone_device *tz)
{ return 0; }

#define thermal_zone_device_disable LINUX_BACKPORT(thermal_zone_device_disable)
static inline int thermal_zone_device_disable(struct thermal_zone_device *tz)
{ return 0; }
#endif /* < 5.9 */

#endif /* __BACKPORT_LINUX_THERMAL_H */

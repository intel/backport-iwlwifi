// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>
#include <linux/thermal.h>

#ifdef CONFIG_THERMAL
struct thermal_zone_device *
thermal_zone_device_register_with_trips(const char *type,
					struct thermal_trip *trips,
					int num_trips, void *devdata,
					struct thermal_zone_device_ops *ops,
					struct thermal_zone_params *tzp, int passive_delay,
					int polling_delay)
{
#if LINUX_VERSION_IS_LESS(6,0,0)
	return thermal_zone_device_register(type, num_trips, 0, devdata, ops, tzp,
					    passive_delay, polling_delay);
#else
#undef thermal_trip
#undef thermal_zone_device_register_with_trips
	return thermal_zone_device_register_with_trips(type,
						       (struct thermal_trip *)(void *) trips,
						       num_trips,
						       0, devdata,
						       ops, tzp, passive_delay,
						       polling_delay);
#define thermal_trip backport_thermal_trip
#define thermal_zone_device_register_with_trips LINUX_BACKPORT(thermal_zone_device_register_with_trips)
#endif /* < 6,6,0 */
}
EXPORT_SYMBOL_GPL(thermal_zone_device_register_with_trips);
#endif /* CONFIG_THERMAL */

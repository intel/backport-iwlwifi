#ifdef CONFIG_THERMAL
#include <linux/thermal.h>
struct backport_thermal_trip {
	int temperature;
	int hysteresis;
	int threshold;
	enum thermal_trip_type type;
	u8 flags;
	void *priv;
};
#define thermal_trip backport_thermal_trip
#endif

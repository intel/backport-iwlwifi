#ifndef __BACKPORT_LINUX_LEDS_H
#define __BACKPORT_LINUX_LEDS_H
#include_next <linux/leds.h>
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,5,0)

static inline void backport_led_trigger_blink_oneshot(struct led_trigger *trigger,
						      unsigned long delay_on,
						      unsigned long delay_off,
						      int invert)
{
	led_trigger_blink_oneshot(trigger, &delay_on, &delay_off, invert);
}
#define led_trigger_blink_oneshot LINUX_BACKPORT(led_trigger_blink_oneshot)

static inline void backport_led_trigger_blink(struct led_trigger *trigger,
					      unsigned long delay_on,
					      unsigned long delay_off)
{
	led_trigger_blink(trigger, &delay_on, &delay_off);
}
#define led_trigger_blink LINUX_BACKPORT(led_trigger_blink)

#endif /*  < 6.5 */

#endif /* __BACKPORT_LINUX_LEDS_H */

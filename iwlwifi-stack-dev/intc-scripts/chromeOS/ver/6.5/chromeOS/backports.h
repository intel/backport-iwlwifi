#include <hdrs/linux/compiler_attributes.h>
#include <linux/leds.h>

#define NL80211_RRF_NO_EHT 0
static inline void
cfg80211_links_removed(struct net_device *dev, u16 removed_links)
{
}

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

#ifndef __cleanup
#define __cleanup(func) __attribute__((__cleanup__(func)))
#endif

static inline u32
iwl7000_ieee80211_mandatory_rates(struct ieee80211_supported_band *sband)
{
	return ieee80211_mandatory_rates(sband, NL80211_BSS_CHAN_WIDTH_20);
}
#define ieee80211_mandatory_rates iwl7000_ieee80211_mandatory_rates

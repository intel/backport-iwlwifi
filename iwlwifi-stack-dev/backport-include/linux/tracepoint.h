/* SPDX-License-Identifier: GPL-2.0 */
/* careful - must be multi-include capable */
#include_next <linux/tracepoint.h>
#ifndef __BP_TRACEPOINT_H
#define __BP_TRACEPOINT_H

#if LINUX_VERSION_IS_LESS(5,10,0)
#define DECLARE_TRACEPOINT(tp) \
	extern struct tracepoint __tracepoint_##tp
#ifdef CONFIG_TRACEPOINTS
# define tracepoint_enabled(tp) \
	static_key_false(&(__tracepoint_##tp).key)
#else
# define tracepoint_enabled(tracepoint) false
#endif
#endif /* < 5.10 */

#endif /* __BP_TRACEPOINT_H */

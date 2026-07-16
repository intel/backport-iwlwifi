/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BACKPORT_LINUX_ONCE_LITE_H
#define _BACKPORT_LINUX_ONCE_LITE_H
#include <linux/version.h>

#if LINUX_VERSION_IS_GEQ(5,14,0)
#include_next <linux/once_lite.h>
#endif

#include <linux/types.h>

#ifndef DO_ONCE_LITE
#define DO_ONCE_LITE(func, ...)						\
	DO_ONCE_LITE_IF(true, func, ##__VA_ARGS__)
#endif

#ifndef __ONCE_LITE_IF
#define __ONCE_LITE_IF(condition)					\
	({								\
		static bool __section(".data..once") __already_done;	\
		bool __ret_cond = !!(condition);			\
		bool __ret_once = false;				\
									\
		if (unlikely(__ret_cond && !__already_done)) {		\
			__already_done = true;				\
			__ret_once = true;				\
		}							\
		unlikely(__ret_once);					\
	})
#endif

#ifndef DO_ONCE_LITE_IF
#define DO_ONCE_LITE_IF(condition, func, ...)				\
	({								\
		bool __ret_do_once = !!(condition);			\
									\
		if (__ONCE_LITE_IF(__ret_do_once))			\
			func(__VA_ARGS__);				\
									\
		unlikely(__ret_do_once);				\
	})
#endif
#endif /* _BACKPORT_LINUX_ONCE_LITE_H */

#ifndef _COMPAT_LINUX_EXPORT_H
#define _COMPAT_LINUX_EXPORT_H 1

#include <linux/version.h>

#if LINUX_VERSION_IS_GEQ(3,2,0)
#include_next <linux/export.h>
#else
#ifndef pr_fmt
#define backport_undef_pr_fmt
#endif
#include <linux/module.h>
#ifdef backport_undef_pr_fmt
#undef pr_fmt
#undef backport_undef_pr_fmt
#endif
#endif /* LINUX_VERSION_IS_GEQ(3,2,0) */

#if LINUX_VERSION_IS_LESS(5,4,0)
#define EXPORT_SYMBOL_NS_GPL(sym, ns) EXPORT_SYMBOL_GPL(sym)
#endif

#endif	/* _COMPAT_LINUX_EXPORT_H */

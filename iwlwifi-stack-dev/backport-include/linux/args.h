#ifndef _BACKPORT_LINUX_ARGS_H
#define _BACKPORT_LINUX_ARGS_H
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,6,0)
#include <linux/kernel.h>
#else
#include_next <linux/args.h>
#endif

#endif /* _BACKPORT_LINUX_ARGS_H */

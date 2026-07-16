#ifndef __BACKPORT_HEX_H
#define __BACKPORT_HEX_H
#include <linux/version.h>
#if LINUX_VERSION_IS_GEQ(6,4,0)
#include_next <linux/hex.h>
#else
#include <linux/kernel.h>
#endif

#endif /* __BACKPORT_HEX_H */

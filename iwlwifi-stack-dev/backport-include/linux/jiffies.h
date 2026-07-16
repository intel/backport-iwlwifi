#ifndef _BACKPORT_JIFFIES_H
#define _BACKPORT_JIFFIES_H

#include_next <linux/jiffies.h>

#ifndef secs_to_jiffies
#define secs_to_jiffies(_secs) (unsigned long)((_secs) * HZ)
#endif

#endif /* _BACKPORT_JIFFIES_H */

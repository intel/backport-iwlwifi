#ifndef __BACKPORT_LINUX_WORKQUEUE_H
#define __BACKPORT_LINUX_WORKQUEUE_H
#include_next <linux/workqueue.h>

#if LINUX_VERSION_IS_LESS(6,17,0)
#define system_dfl_wq system_unbound_wq
#endif

#endif /* __BACKPORT_LINUX_WORKQUEUE_H */

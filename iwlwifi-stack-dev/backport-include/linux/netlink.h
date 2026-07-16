#ifndef __BACKPORT_LINUX_NETLINK_H
#define __BACKPORT_LINUX_NETLINK_H
#include_next <linux/netlink.h>
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(5,0,0)
static inline void nl_set_extack_cookie_u64(struct netlink_ext_ack *extack,
					    u64 cookie)
{
	u64 __cookie = cookie;

	memcpy(extack->cookie, &__cookie, sizeof(__cookie));
	extack->cookie_len = sizeof(__cookie);
}
#endif

/* NL_SET_ERR_MSG_FMT was added in kernel 6.2, but requires _msg_buf field
 * in struct netlink_ext_ack which was also added in 6.2. For older kernels,
 * fall back to NL_SET_ERR_MSG with just the format string (no formatting).
 */
#if LINUX_VERSION_IS_LESS(6,2,0)
#define NL_SET_ERR_MSG_FMT(extack, fmt, args...) \
NL_SET_ERR_MSG((extack), fmt)

#endif

#endif /* __BACKPORT_LINUX_NETLINK_H */

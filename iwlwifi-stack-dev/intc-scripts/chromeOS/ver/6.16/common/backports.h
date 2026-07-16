#ifndef timer_container_of
#define timer_container_of from_timer
#endif

static inline bool
sk_requests_wifi_status(struct sock *sk)
{
	return sk && sk_fullsock(sk) && sock_flag(sk, SOCK_WIFI_STATUS);
}

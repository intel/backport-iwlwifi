#if LINUX_VERSION_IS_LESS(6,11,11)

static inline bool wiphy_delayed_work_pending(struct wiphy *wiphy,
				              struct wiphy_delayed_work *dwork)
{
	return timer_pending(&dwork->timer);
}
#endif

#ifndef _DEFINE_FLEX
#define _DEFINE_FLEX(type, name, member, count, initializer...)				\
	_Static_assert(__builtin_constant_p(count),					\
		       "onstack flex array members require compile-time const count"); 	\
	union {										\
		u8 bytes[sizeof(type) + (count) * sizeof(*((type *)0)->member)];	\
		type obj;								\
	} name##_u initializer;								\
	type *name = (type *)&name##_u

#define DEFINE_RAW_FLEX(type, name, member, count)	\
_DEFINE_FLEX(type, name, member, count, = {})
#endif

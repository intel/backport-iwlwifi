#ifndef __BACKPORT_KERNEL_H
#define __BACKPORT_KERNEL_H
#include_next <linux/kernel.h>
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(4,17,0)

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

#endif /* < 4.17.0 */

#if LINUX_VERSION_IS_LESS(5,10,0)
#undef min
#undef max
#undef clamp
#undef max3
#undef min_t
#undef max_t
#undef min3
#undef clamp_t
#undef __cmp
#undef __careful_cmp
#undef __cmp_once
#include <linux/minmax.h>
#endif

#endif /* __BACKPORT_KERNEL_H */

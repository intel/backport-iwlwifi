#ifndef __BP_KUNIT_TEST_H
#define __BP_KUNIT_TEST_H
#include <linux/version.h>

#include_next <kunit/test.h>

#if LINUX_VERSION_IS_LESS(6,9,0)
/**
 * KUNIT_ARRAY_PARAM_DESC() - Define test parameter generator from an array.
 * @name:  prefix for the test parameter generator function.
 * @array: array of test parameters.
 * @desc_member: structure member from array element to use as description
 *
 * Define function @name_gen_params which uses @array to generate parameters.
 */
#define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)					\
	static const void *name##_gen_params(const void *prev, char *desc)			\
	{											\
		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
		if (__next - (array) < ARRAY_SIZE((array))) {					\
			strscpy(desc, __next->desc_member, KUNIT_PARAM_DESC_SIZE);		\
			return __next;								\
		}										\
		return NULL;									\
	}
#endif /* LINUX_VERSION_IS_LESS(6,6,0) */

#endif /* __BP_KUNIT_TEST_H */

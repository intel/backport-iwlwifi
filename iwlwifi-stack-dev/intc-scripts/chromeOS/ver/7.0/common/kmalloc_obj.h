#ifndef __flex_counter
#define __flex_counter(FAM)	((void *)NULL)
#endif

#ifndef struct_size_t
#define struct_size_t(type, member, count)					\
	struct_size((type *)NULL, member, count)
#endif

#define typeof_flex_counter(FAM)				\
	typeof(_Generic(__flex_counter(FAM),			\
			void *: (size_t)0,			\
			default: *__flex_counter(FAM)))

#define overflows_flex_counter_type(TYPE, FAM, COUNT)		\
	(overflows_type(COUNT, typeof_flex_counter(((TYPE *)NULL)->FAM)))

#define __set_flex_counter(FAM, COUNT)				\
({								\
	*_Generic(__flex_counter(FAM),				\
		  void *:  &(size_t){ 0 },			\
		  default: __flex_counter(FAM)) = (COUNT);	\
})

#define __default_gfp(a,...) a
#define default_gfp(...) __default_gfp(__VA_ARGS__ __VA_OPT__(,) GFP_KERNEL)

#include <linux/bug.h>

#define __alloc_objs(KMALLOC, GFP, TYPE, COUNT)				\
({									\
	const size_t __obj_size = size_mul(sizeof(TYPE), COUNT);	\
	(TYPE *)KMALLOC(__obj_size, GFP);				\
})

#define __alloc_flex(KMALLOC, GFP, TYPE, FAM, COUNT)			\
({									\
	const size_t __count = (COUNT);					\
	const size_t __obj_size = struct_size_t(TYPE, FAM, __count);	\
	TYPE *__obj_ptr = KMALLOC(__obj_size, GFP);			\
	if (__obj_ptr)							\
		__set_flex_counter(__obj_ptr->FAM, __count);		\
	__obj_ptr;							\
})

#define kmalloc_obj(VAR_OR_TYPE, ...) \
	__alloc_objs(kmalloc, default_gfp(__VA_ARGS__), typeof(VAR_OR_TYPE), 1)

#define kmalloc_objs(VAR_OR_TYPE, COUNT, ...) \
	__alloc_objs(kmalloc, default_gfp(__VA_ARGS__), typeof(VAR_OR_TYPE), COUNT)

#define kmalloc_flex(VAR_OR_TYPE, FAM, COUNT, ...) \
	__alloc_flex(kmalloc, default_gfp(__VA_ARGS__), typeof(VAR_OR_TYPE), FAM, COUNT)

#define kzalloc_obj(P, ...) \
	__alloc_objs(kzalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#define kzalloc_objs(P, COUNT, ...) \
	__alloc_objs(kzalloc, default_gfp(__VA_ARGS__), typeof(P), COUNT)
#define kzalloc_flex(P, FAM, COUNT, ...)		\
	__alloc_flex(kzalloc, default_gfp(__VA_ARGS__), typeof(P), FAM, COUNT)

#define kvmalloc_obj(P, ...) \
	__alloc_objs(kvmalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#define kvmalloc_objs(P, COUNT, ...) \
	__alloc_objs(kvmalloc, default_gfp(__VA_ARGS__), typeof(P), COUNT)
#define kvmalloc_flex(P, FAM, COUNT, ...) \
	__alloc_flex(kvmalloc, default_gfp(__VA_ARGS__), typeof(P), FAM, COUNT)

#define kvzalloc_obj(P, ...) \
	__alloc_objs(kvzalloc, default_gfp(__VA_ARGS__), typeof(P), 1)
#define kvzalloc_objs(P, COUNT, ...) \
	__alloc_objs(kvzalloc, default_gfp(__VA_ARGS__), typeof(P), COUNT)
#define kvzalloc_flex(P, FAM, COUNT, ...) \
	__alloc_flex(kvzalloc, default_gfp(__VA_ARGS__), typeof(P), FAM, COUNT)

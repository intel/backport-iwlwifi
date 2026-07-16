
#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#if __has_builtin(__builtin_dynamic_object_size)
#define __struct_size(p)	__builtin_dynamic_object_size(p, 0)
#define __member_size(p)	__builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)
#endif

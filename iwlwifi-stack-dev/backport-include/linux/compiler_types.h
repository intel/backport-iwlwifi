#ifndef _BACKPORTS_LINUX_COMPILER_TYPES_H
#define _BACKPORTS_LINUX_COMPILER_TYPES_H 1
#include_next <linux/compiler_types.h>

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L
# define auto __auto_type
#endif

/*
 * When the size of an allocated object is needed, use the best available
 * mechanism to find it. (For cases where sizeof() cannot be used.)
 */
#if __has_builtin(__builtin_dynamic_object_size)
#define __struct_size(p)	__builtin_dynamic_object_size(p, 0)
#define __member_size(p)	__builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)
#endif

/* normally from compiler-context-analysis.h */
#ifndef __no_context_analysis
#define __no_context_analysis
#endif

/*
 * Optional: only supported since gcc >= 15, clang >= 19
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html#index-_005f_005fbuiltin_005fcounted_005fby_005fref
 * clang: https://clang.llvm.org/docs/LanguageExtensions.html#builtin-counted-by-ref
 */
#if __has_builtin(__builtin_counted_by_ref)
/**
 * __flex_counter() - Get pointer to counter member for the given
 *                    flexible array, if it was annotated with __counted_by()
 * @FAM: Pointer to flexible array member of an addressable struct instance
 *
 * For example, with:
 *
 *	struct foo {
 *		int counter;
 *		short array[] __counted_by(counter);
 *	} *p;
 *
 * __flex_counter(p->array) will resolve to &p->counter.
 *
 * Note that Clang may not allow this to be assigned to a separate
 * variable; it must be used directly.
 *
 * If p->array is unannotated, this returns (void *)NULL.
 */
#define __flex_counter(FAM)	__builtin_counted_by_ref(FAM)
#else
#define __flex_counter(FAM)	((void *)NULL)
#endif

#endif /* _BACKPORTS_LINUX_COMPILER_TYPES_H */

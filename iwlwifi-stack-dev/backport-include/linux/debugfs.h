#ifndef __BACKPORT_DEBUGFS_H_
#define __BACKPORT_DEBUGFS_H_
#include_next <linux/debugfs.h>
#include <linux/version.h>
#include <linux/device.h>

#ifndef DEFINE_DEBUGFS_ATTRIBUTE
#define DEFINE_DEBUGFS_ATTRIBUTE(__fops, __get, __set, __fmt) \
	DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)
#define debugfs_create_file_unsafe(name, mode, parent, data, fops) \
	debugfs_create_file(name, mode, parent, data, fops)
#endif

#if LINUX_VERSION_IS_LESS(5,5,0)
static inline void debugfs_create_xul(const char *name, umode_t mode,
				      struct dentry *parent,
				      unsigned long *value)
{
	if (sizeof(*value) == sizeof(u32))
		debugfs_create_x32(name, mode, parent, (u32 *)value);
	else
		debugfs_create_x64(name, mode, parent, (u64 *)value);
}
#endif

#if LINUX_VERSION_IS_LESS(6,7,0)
struct debugfs_cancellation {
	struct list_head list;
	void (*cancel)(struct dentry *, void *);
	void *cancel_data;
	/* backport only: */
	struct dentry *dentry;
};

void
debugfs_enter_cancellation(struct file *file,
			   struct debugfs_cancellation *cancellation);

void
debugfs_leave_cancellation(struct file *file,
			   struct debugfs_cancellation *cancellation);

#define debugfs_remove LINUX_BACKPORT(debugfs_remove)
void debugfs_remove(struct dentry *dentry);

#if LINUX_VERSION_IS_LESS(5,6,0)
#define debugfs_remove_recursive LINUX_BACKPORT(debugfs_remove_recursive)
void debugfs_remove_recursive(struct dentry *dentry);
#endif
#endif /* < 6.7.0 */

#if LINUX_VERSION_IS_LESS(6,14,0)
static inline int __printf(2, 3) debugfs_change_name(struct dentry *dentry, const char *fmt, ...)
{
	const char *new_name;
	struct dentry *parent;
	va_list ap;

	if (IS_ERR_OR_NULL(dentry))
		return -EINVAL;

	va_start(ap, fmt);
	new_name = kvasprintf_const(GFP_KERNEL, fmt, ap);
	va_end(ap);
	if (!new_name)
		return -ENOMEM;

	parent = dget_parent(dentry);

	debugfs_rename(parent, dentry, parent, new_name);

	dput(parent);
	kfree_const(new_name);
	/* We never checked the succession of debugfs_rename anyway */
	return 0;
}
#endif /* < 6.14.0 */

#endif /* __BACKPORT_DEBUGFS_H_ */

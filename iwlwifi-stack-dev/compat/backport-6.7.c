// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2025 Intel Corporation
 */

#include <linux/list.h>
#include <linux/debugfs.h>

static DEFINE_MUTEX(cancellations_mtx);
static LIST_HEAD(cancellations_list);

void
debugfs_enter_cancellation(struct file *file,
			   struct debugfs_cancellation *cancellation)
{
	cancellation->dentry = file_dentry(file);

	mutex_lock(&cancellations_mtx);
	list_add_tail(&cancellation->list, &cancellations_list);
	mutex_unlock(&cancellations_mtx);
}
EXPORT_SYMBOL_GPL(debugfs_enter_cancellation);

void
debugfs_leave_cancellation(struct file *file,
			   struct debugfs_cancellation *cancellation)
{
	mutex_lock(&cancellations_mtx);
	if (!list_empty(&cancellation->list))
		list_del(&cancellation->list);
	mutex_unlock(&cancellations_mtx);
}
EXPORT_SYMBOL_GPL(debugfs_leave_cancellation);

static bool is_parent_of(struct dentry *p, struct dentry *e)
{
	do {
		if (e == p)
			return true;
		e = e->d_parent;
	} while (!IS_ROOT(e));

	return false;
}

void debugfs_remove(struct dentry *dentry)
{
	struct debugfs_cancellation *cancellation, *tmp;

	mutex_lock(&cancellations_mtx);
	list_for_each_entry_safe(cancellation, tmp, &cancellations_list, list) {
		if (!is_parent_of(dentry, cancellation->dentry))
			continue;
		list_del_init(&cancellation->list);
		cancellation->cancel(cancellation->dentry,
				     cancellation->cancel_data);
	}
	mutex_unlock(&cancellations_mtx);

	/* call the real removal */
#undef debugfs_remove
	debugfs_remove(dentry);
}
EXPORT_SYMBOL_GPL(LINUX_BACKPORT(debugfs_remove));

#if LINUX_VERSION_IS_LESS(5,6,0)
void debugfs_remove_recursive(struct dentry *dentry)
{
	struct debugfs_cancellation *cancellation, *tmp;

	mutex_lock(&cancellations_mtx);
	list_for_each_entry_safe(cancellation, tmp, &cancellations_list, list) {
		if (!is_parent_of(dentry, cancellation->dentry))
			continue;
		list_del_init(&cancellation->list);
		cancellation->cancel(cancellation->dentry,
				     cancellation->cancel_data);
	}
	mutex_unlock(&cancellations_mtx);

	/* call the real removal */
#undef debugfs_remove_recursive
	debugfs_remove_recursive(dentry);
}
EXPORT_SYMBOL_GPL(LINUX_BACKPORT(debugfs_remove_recursive));
#endif

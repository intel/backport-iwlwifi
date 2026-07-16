
static inline void
cfg80211_epcs_changed(struct net_device *netdev, bool enabled)
{
}

DEFINE_GUARD(wiphy, struct wiphy *,
        mutex_lock(&_T->mtx),
        mutex_unlock(&_T->mtx))

static inline int __printf(2, 3) debugfs_change_name(struct dentry *dentry, const char *fmt, ...)
{
	const char *new_name;
	struct dentry *parent;
	va_list ap;

	va_start(ap, fmt);
	new_name = kvasprintf_const(GFP_KERNEL, fmt, ap);
	va_end(ap);
	if (!new_name)
		return -ENOMEM;

	parent = dentry->d_parent;

	debugfs_rename(parent, dentry, parent, new_name);

	kfree_const(new_name);
	/* We never checked the succession of debugfs_rename anyway */
	return 0;
}

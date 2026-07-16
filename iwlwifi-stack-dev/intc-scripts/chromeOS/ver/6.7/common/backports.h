void ieee80211_fragment_element(struct sk_buff *skb, u8 *len_pos, u8 frag_id);

static inline void
_ieee80211_set_sband_iftype_data(struct ieee80211_supported_band *sband,
				 const struct ieee80211_sband_iftype_data *iftd,
				 u16 n_iftd)
{
	sband->iftype_data = iftd;
	sband->n_iftype_data = n_iftd;
}

void wiphy_delayed_work_timer(struct timer_list *t);

#define wiphy_delayed_work_init LINUX_BACKPORT(wiphy_delayed_work_init)
static inline void wiphy_delayed_work_init(struct wiphy_delayed_work *dwork,
					   wiphy_work_func_t func)
{
	timer_setup(&dwork->timer, wiphy_delayed_work_timer, 0);
	wiphy_work_init(&dwork->work, func);
}

void wiphy_work_queue(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_work_cancel(struct wiphy *wiphy, struct wiphy_work *work);

void wiphy_delayed_work_queue(struct wiphy *wiphy,
			      struct wiphy_delayed_work *dwork,
			      unsigned long delay);
void wiphy_delayed_work_cancel(struct wiphy *wiphy,
			       struct wiphy_delayed_work *dwork);

void wiphy_work_flush(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_delayed_work_flush(struct wiphy *wiphy,
			      struct wiphy_delayed_work *work);

#ifndef for_each_sband_iftype_data
#define for_each_sband_iftype_data(sband, i, iftd)	\
	for (i = 0, iftd = &(sband)->iftype_data[i];	\
	     i < (sband)->n_iftype_data;		\
	     i++, iftd = &(sband)->iftype_data[i])
#endif

/* older cfg80211 requires wdev to be locked */
#define WRAP_LOCKED(sym) wdev_locked_ ## sym

static inline void
WRAP_LOCKED(cfg80211_links_removed)(struct net_device *dev, u16 removed_links)
{
	mutex_lock(&dev->ieee80211_ptr->mtx);
	cfg80211_links_removed(dev, removed_links);
	mutex_unlock(&dev->ieee80211_ptr->mtx);
}
#define cfg80211_links_removed WRAP_LOCKED(cfg80211_links_removed)

static inline bool LINUX_BACKPORT(napi_schedule)(struct napi_struct *n)
{
	if (napi_schedule_prep(n)) {
		__napi_schedule(n);
		return true;
	}

	return false;
}
#define napi_schedule LINUX_BACKPORT(napi_schedule)

#ifdef CONFIG_CFG80211_DEBUGFS
static inline
ssize_t wiphy_locked_debugfs_read(struct wiphy *wiphy, struct file *file,
				  char *buf, size_t bufsize,
				  char __user *userbuf, size_t count,
				  loff_t *ppos,
				  ssize_t (*handler)(struct wiphy *wiphy,
						     struct file *file,
						     char *buf,
						     size_t bufsize,
						     void *data),
				  void *data)
{
	ssize_t ret = -EINVAL;

#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_lock(wiphy);
#else
	rtnl_lock();
#endif
	ret = handler(wiphy, file, buf, bufsize, data);
#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_unlock(wiphy);
#else
	rtnl_unlock();
#endif

	if (ret >= 0)
		ret = simple_read_from_buffer(userbuf, count, ppos, buf, ret);

	return ret;
}

static inline
ssize_t wiphy_locked_debugfs_write(struct wiphy *wiphy, struct file *file,
				   char *buf, size_t bufsize,
				   const char __user *userbuf, size_t count,
				   ssize_t (*handler)(struct wiphy *wiphy,
						      struct file *file,
						      char *buf,
						      size_t count,
						      void *data),
				   void *data)
{
	ssize_t ret;

	if (count >= sizeof(buf))
		return -E2BIG;

	if (copy_from_user(buf, userbuf, count))
		return -EFAULT;
	buf[count] = '\0';

#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_lock(wiphy);
#else
	rtnl_lock();
#endif
	ret = handler(wiphy, file, buf, count, data);
#if LINUX_VERSION_IS_GEQ(5,12,0)
	wiphy_unlock(wiphy);
#else
	rtnl_unlock();
#endif

	return ret;
}
#endif
#define KUNIT_STATIC_STUB_REDIRECT(real_fn_name, args...) do {} while (0)

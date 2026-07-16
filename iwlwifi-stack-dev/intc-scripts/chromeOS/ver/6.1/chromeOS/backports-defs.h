struct wiphy;
struct wiphy_work;
typedef void (*wiphy_work_func_t)(struct wiphy *, struct wiphy_work *);

struct wiphy_work {
	struct list_head entry;
	wiphy_work_func_t func;
};

static inline void wiphy_work_init(struct wiphy_work *work,
				   wiphy_work_func_t func)
{
	INIT_LIST_HEAD(&work->entry);
	work->func = func;
}

struct wiphy_delayed_work {
	struct wiphy_work work;
	struct wiphy *wiphy;
	struct timer_list timer;
};

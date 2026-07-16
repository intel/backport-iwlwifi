static inline struct net_device *alloc_netdev_dummy(int sizeof_priv)
{
	struct net_device *dev;
	dev = kzalloc(sizeof(*dev) +
		      ALIGN(sizeof(struct net_device), NETDEV_ALIGN) +
		      sizeof_priv,
		      GFP_KERNEL);
	if (!dev)
		return NULL;
	init_dummy_netdev(dev);
	return dev;
}

static inline void LINUX_BACKPORT(free_netdev)(struct net_device *dev)
{
	if (dev->reg_state == NETREG_DUMMY) {
		kfree(dev);
		return;
	}
	free_netdev(dev);
}
#define free_netdev LINUX_BACKPORT(free_netdev)

#define kmemdup_array LINUX_BACKPORT(kmemdup_array)
static inline void *
kmemdup_array(const void *src, size_t count, size_t element_size, gfp_t gfp)
{
       return kmemdup(src, element_size * count, gfp);
}

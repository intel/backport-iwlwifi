#ifndef __BACKPORT_LINUX_VIRTIO_CONFIG_H
#define __BACKPORT_LINUX_VIRTIO_CONFIG_H
#include_next <linux/virtio_config.h>

#if LINUX_VERSION_IS_LESS(6,11,0)

/**
 * struct virtqueue_info - Info for a virtqueue passed to find_vqs().
 * @name: virtqueue description. Used mainly for debugging, NULL for
 *        a virtqueue unused by the driver.
 * @callback: A callback to invoke on a used buffer notification.
 *            NULL for a virtqueue that does not need a callback.
 * @ctx: A flag to indicate to maintain an extra context per virtqueue.
 */
struct virtqueue_info {
	const char *name;
	vq_callback_t *callback;
	bool ctx;
};

#define virtio_find_vqs LINUX_BACKPORT(virtio_find_vqs)
static inline
int virtio_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
		    struct virtqueue *vqs[],
		    struct virtqueue_info vqs_info[],
		    struct irq_affinity *desc)
{
	vq_callback_t **callbacks = kcalloc(nvqs, sizeof(*callbacks), GFP_KERNEL);
	const char **names = kcalloc(nvqs, sizeof(*names), GFP_KERNEL);
	bool *ctxs = kcalloc(nvqs, sizeof(*ctxs), GFP_KERNEL);
	int ret;

	if (!callbacks || !names || !ctxs) {
		ret = -ENOMEM;
		goto free;
	}

	for (unsigned int i = 0; i < nvqs; i++) {
		callbacks[i] = vqs_info[i].callback;
		names[i] = vqs_info[i].name;
		ctxs[i] = vqs_info[i].ctx;
	}

	ret = vdev->config->find_vqs(vdev, nvqs, vqs, callbacks, names, NULL, desc);
free:
	kfree(callbacks);
	kfree(names);
	kfree(ctxs);
	return ret;
}
#endif /* LINUX_VERSION_IS_LESS(6,11,0) */

#endif /* __BACKPORT_LINUX_VIRTIO_CONFIG_H */

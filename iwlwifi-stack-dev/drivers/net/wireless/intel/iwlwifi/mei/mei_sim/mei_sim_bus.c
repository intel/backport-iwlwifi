// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/device.h>
#include <os.h>
#include <irq_kern.h>
#include <linux/module.h>
#include <linux/init.h>
#include "mei_sim_bus.h"

#ifdef CPTCFG_IWLWIFI_SIMULATION

static struct mei_cl_device *mei_sim_dev;
static struct mei_cl_driver *mei_sim_driver;

static char *csme_path;
module_param(csme_path, charp, 0400);

MODULE_DESCRIPTION("The Intel(R) wireless / MEI bus simulation");
MODULE_LICENSE("GPL");

#define MSG_IDX_INC(idx) (((idx) + 1) % MEI_SIM_RX_MSG_NUM)

void _mei_cldev_set_drvdata(struct mei_cl_device *cldev, void *data)
{
	cldev->priv_data = data;
}
EXPORT_SYMBOL_GPL(_mei_cldev_set_drvdata);

ssize_t _mei_cldev_recv(struct mei_cl_device *cldev, u8 *buf, size_t length)
{
	struct ctrl_msg *msg = &cldev->rx_msgs[cldev->rx_msg_start];

	/* Make sure there is a message ready */
	if (WARN_ON(cldev->rx_msg_start == cldev->rx_msg_end))
		return 0;

	if (length < msg->size) {
		pr_err("mei_cldev_recv: buffer too small (length=%u msglen=%u)\n",
		       length, msg->size);
		return 0;
	}

	memcpy(buf, msg->msg, msg->size);
	return msg->size;
}
EXPORT_SYMBOL_GPL(_mei_cldev_recv);

void *_mei_cldev_get_drvdata(const struct mei_cl_device *cldev)
{
	return cldev->priv_data;
}
EXPORT_SYMBOL_GPL(_mei_cldev_get_drvdata);

int _mei_cldev_enable(struct mei_cl_device *cldev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(_mei_cldev_enable);

bool _mei_cldev_enabled(struct mei_cl_device *cldev)
{
	return mei_sim_dev;
}
EXPORT_SYMBOL_GPL(_mei_cldev_enabled);

int _mei_cldev_disable(struct mei_cl_device *cldev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(_mei_cldev_disable);

static void _wait_ack(struct mei_cl_device *cldev)
{
	int rc;
	u64 ack;

	/*
	 * The ack message is received in the interrupt handler for rx messages.
	 * However, waiting for the cldev->sock_fd to become readable is racy
	 * since the interrupt may already been processed, in which case this
	 * will wait forever.
	 * To workaround this, the interrupt handler signals the ack on the
	 * event_fd, to which we can safely wait here.
	 */
	time_travel_wait_readable(cldev->event_fd);
	rc = os_read_file(cldev->event_fd, &ack, sizeof(ack));
	WARN_ON(rc < 0 || ack != 1);
}

static size_t __mei_cldev_send(struct mei_cl_device *cldev,
			       u8 *buf, size_t len, int *fds,
			       unsigned int num_fds)
{
	struct ctrl_msg msg = {
		.size = len,
	};
	int ret;

	if (len > sizeof(msg.msg)) {
		pr_err("mei_cldev_send: message too long (length=%u)\n", len);
		return -ENOBUFS;
	}

	/*
	 * Zero length means it is an ack, in which case no need to update time
	 */
	if (len) {
		memcpy(msg.msg, buf, len);
		time_travel_propagate_time();
	}

	ret = os_sendmsg_fds(cldev->sock_fd, &msg, sizeof(msg.size) + len, fds,
			     num_fds);
	if (ret < (int)sizeof(msg.size)) {
		pr_err("_mei_cldev_send_with_ack: failed (ret=%d)\n", ret);
		return ret;
	}

	if (len)
		_wait_ack(cldev);

	/* return how many bytes were sent without the message header */
	return ret - sizeof(msg.size);
}

static int mei_cldev_read_msg(struct mei_cl_device *cldev,
			      struct time_travel_event *ev)
{
	struct ctrl_msg *rx_msg = &cldev->rx_msgs[cldev->rx_msg_end];
	int ret;

	if (WARN_ON(MSG_IDX_INC(cldev->rx_msg_end) == cldev->rx_msg_start)) {
		pr_err("%s: Message buffers are full\n", __func__);
		return 0;
	}

	ret = os_read_file(cldev->sock_fd, rx_msg, sizeof(*rx_msg));
	if (ret != (int)sizeof(rx_msg->size) + rx_msg->size) {
		pr_err("%s: Failed to read message\n", __func__);
		return ret;
	}

	/* Zero length message is an ack. Signal that ack was received. */
	if (rx_msg->size == 0) {
		u64 n = 1;

		ret = os_write_file(cldev->event_fd, &n, sizeof(n));
		WARN_ON(ret < 0);
		return 0;
	}

	if (ev)
		time_travel_add_irq_event(ev);

	cldev->rx_msg_end = MSG_IDX_INC(cldev->rx_msg_end);

	__mei_cldev_send(cldev, NULL, 0, NULL, 0);

	return rx_msg->size;
}

size_t _mei_cldev_send(struct mei_cl_device *cldev, u8 *buf, size_t length)
{
	return __mei_cldev_send(cldev, buf, length, NULL, 0);
}
EXPORT_SYMBOL_GPL(_mei_cldev_send);

static irqreturn_t mei_cldev_interrupt(int irq, void *data)
{
	struct mei_cl_device *cldev = data;

	if (!um_irq_timetravel_handler_used())
		mei_cldev_read_msg(cldev, NULL);

	schedule_work(&cldev->rx_work);

	return IRQ_HANDLED;
}

static void mei_cldev_interrupt_comm_handler(int irq, int fd, void *data,
					     struct time_travel_event *ev)
{
	mei_cldev_read_msg(data, ev);
}

static void mei_cldev_rx_wk(struct work_struct *wk)
{
	struct mei_cl_device *cldev = container_of(wk, struct mei_cl_device,
						   rx_work);

	while (cldev->rx_msg_start != cldev->rx_msg_end) {
		cldev->rx_cb(cldev);
		cldev->rx_msg_start = MSG_IDX_INC(cldev->rx_msg_start);
	}
}

int _mei_cldev_register_rx_cb(struct mei_cl_device *cldev, mei_cldev_cb_t rx_cb)
{
	cldev->rx_cb = rx_cb;
	return 0;
}
EXPORT_SYMBOL_GPL(_mei_cldev_register_rx_cb);

int _mei_cldev_dma_unmap(struct mei_cl_device *cldev)
{
	return 0;
}
EXPORT_SYMBOL_GPL(_mei_cldev_dma_unmap);

void *_mei_cldev_dma_map(struct mei_cl_device *cldev,
			 u8 buffer_id, size_t size)
{
	void *addr = NULL;
	int fd;
	struct {
		u32 size;
		u64 offset;
	} __packed fd_msg;
	int ret;

	addr = kmalloc(size, GFP_KERNEL);
	if (!addr)
		return NULL;

	fd = phys_mapping(to_phys(addr), &fd_msg.offset);
	if (fd < 0) {
		pr_err("mei: failed to allocate DMA mem\n");
		kfree(addr);
		return NULL;
	}

	fd_msg.size = size;

	ret = __mei_cldev_send(cldev, (void *)&fd_msg, sizeof(fd_msg), &fd, 1);
	if (ret < (int)sizeof(fd_msg)) {
		kfree(addr);
		return NULL;
	}

	return addr;
}
EXPORT_SYMBOL_GPL(_mei_cldev_dma_map);

static int mei_sim_match(struct device *dev, struct device_driver *driver)
{
	/* Only have 1 device and 1 driver registered, so should always be ok */
	return 1;
}

static struct bus_type mei_sim_bus = {
	.name = "mei_sim_bus",
	.match = mei_sim_match,
};

static void mei_sim_bus_dev_release(struct device *dev)
{
}

static int mei_sim_bus_register_device(struct mei_cl_device *cldev)
{
	cldev->dev.bus = &mei_sim_bus;
	cldev->dev.release = mei_sim_bus_dev_release;
	dev_set_name(&cldev->dev, "me_sim_dev");

	return device_register(&cldev->dev);
}

static struct mei_cl_device *mei_sim_new_cldev(void)
{
	struct mei_cl_device *cldev;

	/* If csme_path is not given, assume CSME is not running */
	if (!csme_path)
		return NULL;

	cldev = kzalloc(sizeof(*cldev), GFP_KERNEL);
	if (WARN_ON(!cldev))
		return NULL;

	snprintf(cldev->name, sizeof(cldev->name), "mei_sim_dev");

	cldev->sock_fd = os_connect_socket(csme_path);
	if (WARN_ON(cldev->sock_fd < 0)) {
		pr_err("%s: os_connect_socket failed, ret=%d path=%s", __func__,
		       cldev->sock_fd, csme_path);
		goto out;
	}

	cldev->event_fd = os_eventfd(0, 0);
	if (WARN_ON(cldev->event_fd < 0))
		goto out;

	INIT_WORK(&cldev->rx_work, mei_cldev_rx_wk);

	cldev->irq = um_request_irq_tt(UM_IRQ_ALLOC, cldev->sock_fd, IRQ_READ,
				       mei_cldev_interrupt, IRQF_SHARED,
				       cldev->name, cldev,
				       mei_cldev_interrupt_comm_handler);
	if (WARN_ON(cldev->irq < 0)) {
		pr_err("%s: failed to register irq handler (ret=%d)\n",
		       __func__, cldev->irq);
		goto free_eventfd;
	}

	return cldev;

free_eventfd:
	os_close_file(cldev->event_fd);
out:
	kfree(cldev);
	return NULL;
}

static int __init mei_sim_bus_init(void)
{
	int err;

	err = bus_register(&mei_sim_bus);
	if (err)
		return err;

	/*
	 * Load the bus even if adding a device fails (e.g. socket path is not given)
	 * This will allow to run without CSME as well (iwlmei will register to this
	 * bus successfully, but there is no device).
	 */
	mei_sim_dev = mei_sim_new_cldev();
	if (!mei_sim_dev)
		return 0;

	err = mei_sim_bus_register_device(mei_sim_dev);
	if (err)
		goto out;

	return 0;

out:
	kfree(mei_sim_dev);
	bus_unregister(&mei_sim_bus);
	return err;
}
module_init(mei_sim_bus_init);

static void __exit mei_sim_bus_exit(void)
{
	if (mei_sim_dev) {
		um_free_irq(mei_sim_dev->irq, mei_sim_dev);
		cancel_work_sync(&mei_sim_dev->rx_work);
		os_close_file(mei_sim_dev->sock_fd);
		os_close_file(mei_sim_dev->event_fd);
		kfree(mei_sim_dev);
	}

	bus_unregister(&mei_sim_bus);
	pr_debug("mei: exit\n");
}
module_exit(mei_sim_bus_exit);

static int mei_sim_probe(struct device *dev)
{
	struct mei_cl_device *cldev = container_of(dev, struct mei_cl_device, dev);

	return mei_sim_driver->probe(cldev, mei_sim_driver->id_table);
}

int mei_sim_driver_register(struct mei_cl_driver *cldrv)
{
	int err;

	/* Only one driver is supported */
	if (WARN_ON(mei_sim_driver))
		return -ENOBUFS;

	mei_sim_driver = cldrv;

	pr_debug("mei driver registered %s\n", cldrv->name);
	cldrv->driver.name = cldrv->name;
	cldrv->driver.bus = &mei_sim_bus;
	cldrv->driver.probe = mei_sim_probe;
	err = driver_register(&cldrv->driver);
	return err;
}
EXPORT_SYMBOL_GPL(mei_sim_driver_register);

void mei_sim_driver_unregister(struct mei_cl_driver *cldrv)
{
	driver_unregister(&cldrv->driver);
}
EXPORT_SYMBOL_GPL(mei_sim_driver_unregister);
#endif

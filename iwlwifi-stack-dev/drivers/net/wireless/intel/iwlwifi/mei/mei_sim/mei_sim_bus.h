/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef __mei_sim_h__
#define __mei_sim_h__

#include <linux/device.h>
#include <os.h>
#include <irq_kern.h>
#include <linux/uuid.h>

#define MEI_CL_VERSION_ANY 0xff
#define MEI_CL_NAME_SIZE 32

struct mei_cl_device;

typedef void (*mei_cldev_cb_t)(struct mei_cl_device *cldev);

struct mei_cl_device_id {
	char name[MEI_CL_NAME_SIZE];
	uuid_le uuid;
	__u8    version;
	unsigned long driver_info;
};

struct ctrl_msg {
	u32 size;
	u8 msg[100];
} __packed;

#define MEI_SIM_RX_MSG_NUM	10

struct mei_cl_device {
	struct list_head bus_list;
	struct device dev;
	char name[32];
	int irq;
	int sock_fd;
	int event_fd;
	struct ctrl_msg rx_msgs[MEI_SIM_RX_MSG_NUM];
	u32 rx_msg_start;
	u32 rx_msg_end;
	struct work_struct rx_work;
	mei_cldev_cb_t rx_cb;
	void *dma_addr;
	void *priv_data;
};

struct mei_cl_driver {
	struct device_driver driver;
	const char *name;

	const struct mei_cl_device_id *id_table;

	int (*probe)(struct mei_cl_device *cldev,
		     const struct mei_cl_device_id *id);
	void (*remove)(struct mei_cl_device *cldev);
};

void _mei_cldev_set_drvdata(struct mei_cl_device *cldev, void *data);
ssize_t _mei_cldev_recv(struct mei_cl_device *cldev, u8 *buf, size_t length);
void *_mei_cldev_get_drvdata(const struct mei_cl_device *cldev);

int _mei_cldev_enable(struct mei_cl_device *cldev);

bool _mei_cldev_enabled(struct mei_cl_device *cldev);

int _mei_cldev_disable(struct mei_cl_device *cldev);

size_t _mei_cldev_send(struct mei_cl_device *cldev, u8 *buf, size_t length);
int _mei_cldev_register_rx_cb(struct mei_cl_device *cldev, mei_cldev_cb_t rx_cb);
int _mei_cldev_dma_unmap(struct mei_cl_device *cldev);
void *_mei_cldev_dma_map(struct mei_cl_device *cldev,
			 u8 buffer_id, size_t size);
int mei_sim_driver_register(struct mei_cl_driver *cldrv);
void mei_sim_driver_unregister(struct mei_cl_driver *cldrv);

#define mei_cldev_set_drvdata(cldev, data) _mei_cldev_set_drvdata(cldev, data)

#define mei_cldev_recv(cldev, buf, length) _mei_cldev_recv(cldev, buf, length)

#define mei_cldev_get_drvdata(cldev) _mei_cldev_get_drvdata(cldev)

#define mei_cldev_enable(cldev) _mei_cldev_enable(cldev)

#define mei_cldev_enabled(cldev) _mei_cldev_enabled(cldev)

#define mei_cldev_disable(cldev) _mei_cldev_disable(cldev)

#define mei_cldev_send(cldev, buf, length) _mei_cldev_send(cldev, buf, length)

#define mei_cldev_register_rx_cb(cldev, rx_cb) _mei_cldev_register_rx_cb(cldev, rx_cb)

#define mei_cldev_dma_unmap(cldev) _mei_cldev_dma_unmap(cldev)

#define mei_cldev_dma_map(cldev, buffer_id, size) _mei_cldev_dma_map(cldev, buffer_id, size)

#define module_mei_cl_driver(__mei_cldrv) \
	module_driver(__mei_cldrv, mei_sim_driver_register, mei_sim_driver_unregister)
#endif

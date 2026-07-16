// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2023-2024 Intel Corporation
 */
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/debugfs.h>

static struct dentry *vlab_control_dbgfs;

struct vlab_control_device {
	struct virtio_device *vdev;
	struct virtqueue *cmd_vq;
	struct dentry *debugfs_dir;
	bool registered;
};

struct vlab_control_message {
	struct completion done;
	char message[128];
	char response[128];
};

static int vlab_control_send_message(struct vlab_control_device *dev,
				     struct vlab_control_message *msg)
{
	struct scatterlist message_sg, response_sg;
	struct scatterlist *sgs[2] = { &message_sg, &response_sg };
	int err;

	sg_init_one(&message_sg, msg->message, sizeof(msg->message));
	sg_init_one(&response_sg, msg->response, sizeof(msg->response));
	init_completion(&msg->done);

	err = virtqueue_add_sgs(dev->cmd_vq, sgs, 1, 1, msg, GFP_KERNEL);
	if (err)
		return err;
	virtqueue_kick(dev->cmd_vq);

	wait_for_completion(&msg->done);
	return 0;
}

static ssize_t vlab_control_write(struct file *file, const char __user *userbuf,
				  size_t count, loff_t *ppos)
{
	struct vlab_control_device *dev = file->private_data;
	struct vlab_control_message *msg;
	ssize_t err;

	/* keep it NUL-terminated */
	if (count >= sizeof(msg->message))
		return -EINVAL;

	msg = kzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	if (copy_from_user(msg->message, userbuf, count)) {
		err = -EFAULT;
		goto free;
	}

	err = vlab_control_send_message(dev, msg);
	if (!err)
		err = count;
free:
	kfree(msg);
	return err;
}

static const struct file_operations vlab_control_ops = {
	.open = simple_open,
	.write = vlab_control_write,
};

static void vlab_control_add_debugfs(struct vlab_control_device *dev,
				     struct vlab_control_message *msg)
{
	const char *name = msg->response;
	size_t len = strnlen(name, sizeof(msg->response));

	if (WARN_ON(len == 0 ||
		    len == sizeof(msg->response)))
		return;

	/*
	 * This is clearly unsafe - we're giving an uncontrolled
	 * buffer to kernel internal functions, what if it has an
	 * invalid character like / ... but we don't care since
	 * this is only simulation code! Just don't copy it!
	 */
	dev->debugfs_dir = debugfs_create_dir(name, vlab_control_dbgfs);
	debugfs_create_file("control", 0200, dev->debugfs_dir,
			    dev, &vlab_control_ops);
}

static void vlab_control_vq_cb(struct virtqueue *vq)
{
	struct vlab_control_message *msg;
	unsigned int len;

	while ((msg = virtqueue_get_buf(vq, &len)))
		complete(&msg->done);
}

static int vlab_control_init_vqs(struct vlab_control_device *dev)
{
	struct virtqueue *vqs[1];
	struct virtqueue_info vqs_info[1] = {
		[0] = { "control", vlab_control_vq_cb },
	};
	int err;

	err = virtio_find_vqs(dev->vdev, 1, vqs, vqs_info, NULL);
	if (err)
		return err;

	dev->cmd_vq = vqs[0];

	virtio_device_ready(dev->vdev);

	return 0;
}

static int vlab_control_probe(struct virtio_device *vdev)
{
	struct vlab_control_device *dev;
	struct vlab_control_message *init_msg = NULL;
	int err;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->vdev = vdev;
	vdev->priv = dev;

	init_msg = kzalloc(sizeof(*init_msg), GFP_KERNEL);
	if (!init_msg) {
		err = -ENOMEM;
		goto error;
	}

	err = vlab_control_init_vqs(dev);
	if (err)
		goto error;

	strscpy(init_msg->message, "get-id", sizeof(init_msg->message));
	err = vlab_control_send_message(dev, init_msg);
	if (!WARN_ON(err))
		vlab_control_add_debugfs(dev, init_msg);
	kfree(init_msg);

	return 0;
error:
	kfree(init_msg);
	kfree(dev);
	return err;
}

static void vlab_control_remove(struct virtio_device *vdev)
{
	struct vlab_control_device *dev = vdev->priv;

	/* Stop all virtqueues */
	virtio_reset_device(vdev);
	vdev->config->del_vqs(vdev);

	debugfs_remove_recursive(dev->debugfs_dir);
	kfree(dev);
}

static struct virtio_device_id id_table[] = {
	{ 2000, VIRTIO_DEV_ANY_ID },
	{ 0 },
};
MODULE_DEVICE_TABLE(virtio, id_table);

static struct virtio_driver vlab_control_driver = {
	.driver.name = "virtio-vlab-control",
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = vlab_control_probe,
	.remove = vlab_control_remove,
};

static int __init vlab_control_init(void)
{
	vlab_control_dbgfs = debugfs_create_dir("vlab-control", NULL);

	return register_virtio_driver(&vlab_control_driver);
}
module_init(vlab_control_init);

static void __exit vlab_control_exit(void)
{
	unregister_virtio_driver(&vlab_control_driver);
	debugfs_remove_recursive(vlab_control_dbgfs);
}
module_exit(vlab_control_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vlab control module");

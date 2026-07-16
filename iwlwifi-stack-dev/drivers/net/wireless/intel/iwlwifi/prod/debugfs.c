// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2026 Intel Corporation
 */
#include <linux/hex.h>
#include "prod.h"
#include "iwl-trans.h"
#include "fw/dbg.h"
#include "fw/api/smart-tester.h"

static ssize_t iwl_dbgfs_smart_tester_cmd_read(struct iwl_prod *prod,
					       size_t count, char **buf)
{
	u32 rsp_addr = le32_to_cpu(prod->fw->smart_tester.smem.rsp_addr);
	u32 rsp_size = le32_to_cpu(prod->fw->smart_tester.smem.rsp_size);
	u32 rsp_hdr_size = sizeof(struct iwl_smart_tester_cmd_rsp);
	u32 rsp_data_size = 0;
	u32 rsp_size_dwords = 0;
	struct iwl_smart_tester_cmd_rsp *rsp_buf;
	size_t buf_size, ret, i, pos = 0;
	__le32 *ptr;

	if (!iwl_prod_firmware_running(prod))
		return -EIO;

	/* allocate max response buf size */
	rsp_buf = kzalloc(rsp_size, GFP_KERNEL);
	if (!rsp_buf)
		return -ENOMEM;

	/* first read the response header to check if the response buffer
	 * is valid and get the actual response size
	 */
	iwl_trans_read_mem_bytes(prod->trans, rsp_addr, rsp_buf,
				 rsp_hdr_size);

	/* skip reading the actual data as it's invalid */
	if (!rsp_buf->hdr.is_valid || !rsp_buf->hdr.length)
		goto out;

	/* truncate hdr.length (after converting from dwords to bytes) if
	 * it exceeds the maximum response data length (alraedy in bytes)
	 */
	rsp_data_size = min(le32_to_cpu(rsp_buf->hdr.length) << 2,
			    rsp_size - rsp_hdr_size);

	/* read the response data */
	iwl_trans_read_mem_bytes(prod->trans, rsp_addr + rsp_hdr_size,
				 &rsp_buf->data, rsp_data_size);
out:
	/* for now, the return format is just a space separated hex bytes.
	 * convert the hdr+data size from bytes to dwords and allocate
	 * max buf size, given that for each dword we need up to 10 chars
	 * (including 0x) + space and a \n at the end.
	 */
	rsp_size_dwords = (rsp_data_size + rsp_hdr_size) >> 2;
	buf_size = rsp_size_dwords * 12 + 1;
	*buf = kzalloc(buf_size, GFP_KERNEL);
	if (!*buf) {
		ret = -ENOMEM;
		goto out_free;
	}

	ptr = (__le32 *)rsp_buf;
	for (i = 0; i < rsp_size_dwords; i++)
		pos += scnprintf(*buf + pos, buf_size - pos, "%#02x ", ptr[i]);
	pos += scnprintf(*buf + pos, buf_size - pos, "\n");
	ret = pos;

out_free:
	/* buf will be freed in debugfs release callback */
	kfree(rsp_buf);
	return ret;
}

struct iwl_smart_tester_cmd_write_data {
	__be32 is_valid;
	__be32 length;
	__be32 ver_id;
	__be32 id;
	__be32 data[];
} __packed;

static ssize_t iwl_dbgfs_smart_tester_cmd_write(struct iwl_prod *prod,
						char *buf, size_t count)
{
	struct iwl_smart_tester_cmd_write_data *input = NULL;
	struct iwl_smart_tester_cmd_rsp *tester_cmd = NULL;
	/* The input consists of a stream of dwords represented as hex chars
	 * without the 0x prefix. Each dword is comprised of 8 characters,
	 * which equals 8 bytes. As the size is dword aligned (4 bytes),
	 * need to divide the count by 2 to convert it to bytes.
	 */
	size_t input_nbytes = count / 2;
	size_t min_input_nbytes =
		sizeof(struct iwl_smart_tester_cmd_write_data);
	size_t max_input_nbytes =
		le32_to_cpu(prod->fw->smart_tester.smem.cmd_size);
	u32 len_dwords, expected_input_bytes, i;
	int ret;

	BUILD_BUG_ON(sizeof(struct iwl_smart_tester_cmd_write_data) !=
		     sizeof(struct iwl_smart_tester_cmd_rsp));

	if (!iwl_prod_firmware_running(prod))
		return -EIO;

	if (input_nbytes < min_input_nbytes) {
		IWL_ERR(prod,
			"Smart Tester cmd input is too small (%ld/%ld)\n",
			count, min_input_nbytes);
		return -EINVAL;
	}

	if (input_nbytes > max_input_nbytes) {
		IWL_ERR(prod,
			"Smart Tester cmd input is too big (%ld/%ld)\n",
			count, max_input_nbytes);
		return -EINVAL;
	}

	input = kmalloc(input_nbytes, GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	ret = hex2bin((u8 *)input, buf, input_nbytes);
	if (ret) {
		IWL_ERR(prod, "Smart tester hex2bin failed (%d)\n", ret);
		goto out;
	}

	len_dwords = be32_to_cpu(input->length);

	expected_input_bytes = sizeof(*input) + len_dwords * sizeof(u32);
	if (input_nbytes != expected_input_bytes) {
		IWL_ERR(prod,
			"Smart tester cmd input length mismatch (%ld/%d)\n",
			count, expected_input_bytes);
		ret = -EINVAL;
		goto out;
	}

	tester_cmd = kzalloc(input_nbytes, GFP_KERNEL);
	if (!tester_cmd) {
		ret = -ENOMEM;
		goto out;
	}

	tester_cmd->hdr.is_valid = cpu_to_le32(be32_to_cpu(input->is_valid));
	tester_cmd->hdr.length = cpu_to_le32(len_dwords);
	tester_cmd->hdr.ver_id = cpu_to_le32(be32_to_cpu(input->ver_id));
	tester_cmd->id = cpu_to_le32(be32_to_cpu(input->id));

	for (i = 0; i < len_dwords; i++)
		tester_cmd->data[i] = cpu_to_le32(be32_to_cpu(input->data[i]));

	ret = iwl_smart_tester_send_cmd(prod, tester_cmd);
	if (ret)
		iwl_prod_fatal_error(prod);

out:
	kfree(tester_cmd);
	kfree(input);
	return ret ?: count;
}

#define START_FW_BUFSIZE	7

static ssize_t iwl_dbgfs_start_fw_write(struct file *file,
					const char __user *user_buf,
					size_t count,
					loff_t *ppos)
{
	struct iwl_prod *prod = file->private_data;
	char buf[START_FW_BUFSIZE] = {};
	int ret;

	if (count != START_FW_BUFSIZE - 1)
		return -EINVAL;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	/* in future we may want to have special modes for starting
	 * the firmware, for now simply start it normally
	 */
	if (strcmp(buf, "start\n"))
		return -EINVAL;

	if (iwl_prod_firmware_running(prod))
		return -EALREADY;

	ret = iwl_prod_run_fw(prod);
	if (ret)
		return ret;

	return count;
}

static ssize_t iwl_dbgfs_fw_nmi_write(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct iwl_prod *prod = file->private_data;

	if (!iwl_prod_firmware_running(prod))
		return -EIO;

	iwl_force_nmi(prod->trans);

	/* there are no interrupts from firmware so we need to wait a bit
	 * and then trigger firmware dump collection
	 */
	msleep_interruptible(5);

	set_bit(STATUS_FW_ERROR, &prod->trans->status);

	iwl_fw_error_collect(&prod->fwrt);

	/* we don't need to reset the device - just stop it and let userspace
	 * to determine whether to unload the driver or restart firmware
	 */
	iwl_prod_stop_device(prod);

	return count;
}

static const struct file_operations iwl_dbgfs_start_fw_ops = {
	.write = iwl_dbgfs_start_fw_write,
	.open = simple_open,
	.llseek = generic_file_llseek,
};

static const struct file_operations iwl_dbgfs_fw_nmi_ops = {
	.write = iwl_dbgfs_fw_nmi_write,
	.open = simple_open,
	.llseek = generic_file_llseek,
};

#define PROD_DEBUGFS_OPEN_WRAPPER(name, argtype)			\
struct dbgfs_##name##_data {						\
	argtype *arg;							\
	bool read_done;							\
	ssize_t rlen;							\
	size_t rbuf_len;						\
	char *rbuf;							\
};									\
static int _iwl_dbgfs_##name##_open(struct inode *inode,		\
				    struct file *file)			\
{									\
	struct dbgfs_##name##_data *data;				\
									\
	data = kzalloc(sizeof(*data), GFP_KERNEL);			\
	if (!data)							\
		return -ENOMEM;						\
	data->arg = inode->i_private;					\
	data->read_done = false;					\
	/* will be allocated by the read function */			\
	data->rbuf = NULL;						\
	data->rbuf_len = 0;						\
	file->private_data = data;					\
	return 0;							\
}

#define PROD_DEBUGFS_READ_WRAPPER(name)					\
static ssize_t _iwl_dbgfs_##name##_read(struct file *file,		\
					char __user *user_buf,		\
					size_t count, loff_t *ppos)	\
{									\
	struct dbgfs_##name##_data *data = file->private_data;		\
									\
	if (!data->read_done) {						\
		data->read_done = true;					\
		data->rlen = iwl_dbgfs_##name##_read(data->arg,		\
						     data->rbuf_len,	\
						     &data->rbuf);	\
	}								\
									\
	if (data->rlen < 0)						\
		return data->rlen;					\
	if (!data->rbuf)						\
		return -EINVAL;						\
	return simple_read_from_buffer(user_buf, count, ppos,		\
				       data->rbuf, data->rlen);		\
}

#define PROD_DEBUGFS_WRITE_WRAPPER(name, argtype)			\
static ssize_t _iwl_dbgfs_##name##_write(struct file *file,		\
					 const char __user *user_buf,	\
					 size_t count, loff_t *ppos)	\
{									\
	ssize_t res;							\
	argtype *arg =							\
		((struct dbgfs_##name##_data *)file->private_data)->arg;\
	char *buf = kmalloc(count + 1, GFP_KERNEL);			\
	if (!buf)							\
		return -ENOMEM;						\
									\
	if (copy_from_user(buf, user_buf, count)) {			\
		res = -EFAULT;						\
		goto out;						\
	}								\
	buf[count] = '\0';						\
	res = iwl_dbgfs_##name##_write(arg, buf, count);		\
out:									\
	kfree(buf);							\
	return res;							\
}

#define PROD_DEBUGFS_RELEASE_WRAPPER(name)				\
static int _iwl_dbgfs_##name##_release(struct inode *inode,		\
				       struct file *file)		\
{									\
	struct dbgfs_##name##_data *data = file->private_data;		\
									\
	kfree(data->rbuf);						\
	kfree(data);							\
	return 0;							\
}

#define _PROD_DEBUGFS_READ_WRITE_FILE_OPS(name, argtype)		\
PROD_DEBUGFS_OPEN_WRAPPER(name, argtype)				\
PROD_DEBUGFS_READ_WRAPPER(name)						\
PROD_DEBUGFS_WRITE_WRAPPER(name, argtype)				\
PROD_DEBUGFS_RELEASE_WRAPPER(name)					\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write = _iwl_dbgfs_##name##_write,				\
	.read = _iwl_dbgfs_##name##_read,				\
	.open = _iwl_dbgfs_##name##_open,				\
	.release = _iwl_dbgfs_##name##_release,				\
	.llseek = generic_file_llseek,					\
}

#define PROD_DEBUGFS_READ_WRITE_FILE_OPS(name)				\
	_PROD_DEBUGFS_READ_WRITE_FILE_OPS(name, struct iwl_prod)

#define PROD_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, prod,			\
			    &iwl_dbgfs_##name##_ops);			\
	} while (0)
#define PROD_DEBUGFS_ADD_FILE(name, parent, mode)			\
	PROD_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

PROD_DEBUGFS_READ_WRITE_FILE_OPS(smart_tester_cmd);

int iwl_prod_dbgfs_register(struct iwl_prod *prod, struct dentry *dbgfs_dir)
{
	debugfs_create_file("start_fw", 0200, dbgfs_dir,
			    prod, &iwl_dbgfs_start_fw_ops);
	debugfs_create_file("fw_nmi", 0200, dbgfs_dir,
			    prod, &iwl_dbgfs_fw_nmi_ops);
	PROD_DEBUGFS_ADD_FILE(smart_tester_cmd, dbgfs_dir, 0600);

	return 0;
}

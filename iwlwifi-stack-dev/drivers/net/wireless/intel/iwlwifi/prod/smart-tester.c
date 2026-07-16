// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#include <linux/kernel.h>
#include <linux/errno.h>

#include "iwl-io.h"
#include "iwl-prph.h"
#include "iwl-trans.h"
#include "fw/api/smart-tester.h"
#include "fw/dbg.h"
#include "prod.h"

int iwl_smart_tester_get_cmd_timeout(struct iwl_prod *prod, u32 cmd_id)
{
	const struct iwl_smart_tester *tester = &prod->fw->smart_tester;
	struct iwl_smart_tester_cmd_timeout_pair *entry;
	unsigned int i;

	entry = tester->cmds_timeout;
	for (i = 0; i < tester->n_cmds_timeout; i++, entry++)
		if (le16_to_cpu(entry->cmd_id) == cmd_id)
			return le16_to_cpu(entry->timeout);

	return -EINVAL;
}

int iwl_smart_tester_wait_for_rsp(struct iwl_prod *prod, u32 id)
{
	const struct iwl_smart_tester *tester = &prod->fw->smart_tester;
	u32 rsp_addr = le32_to_cpu(tester->smem.rsp_addr);
	struct iwl_trans *trans = prod->trans;
	struct iwl_smart_tester_cmd_rsp buf;
	int timeout;

	timeout = iwl_smart_tester_get_cmd_timeout(prod, id);
	if (timeout < 0) {
		IWL_ERR(trans,
			"Failed to get cmd/rsp id %d timeout value\n", id);
		return timeout;
	}

	/* waiting response buffer to be available */
	IWL_DEBUG_FW(trans, "wait %dms before read response (id=0x%x)\n",
		     timeout, id);

	if (msleep_interruptible(timeout)) {
		IWL_ERR(trans, "error: sleep interrupted!\n");
		return -1;
	}

	iwl_trans_read_mem_bytes(trans, rsp_addr, &buf, sizeof(buf));

	IWL_DEBUG_FW(trans, "response: valid=0x%x len=0x%x ver=0x%x id=0x%x\n",
		     buf.hdr.is_valid, buf.hdr.length, buf.hdr.ver_id,
		     buf.id);

	if (le32_to_cpu(buf.hdr.is_valid) != SMART_TESTER_BUF_IS_VALID) {
		IWL_ERR(trans,
			"timeout: invalid response buffer (is_valid=0x%x)\n",
			le32_to_cpu(buf.hdr.is_valid));
		return -ETIMEDOUT;
	}

	if (le32_to_cpu(buf.id) != id) {
		IWL_ERR(trans, "unexpected response id=0x%x (expected 0x%x)\n",
			le32_to_cpu(buf.id), id);
		return -EINVAL;
	}

	return 0;
}

int iwl_smart_tester_send_cmd(struct iwl_prod *prod,
			      struct iwl_smart_tester_cmd_rsp *cmd)
{
	u32 cmd_addr = le32_to_cpu(prod->fw->smart_tester.smem.cmd_addr);
	u32 max_cmd_size = le32_to_cpu(prod->fw->smart_tester.smem.cmd_size);
	u32 cmd_size = sizeof(*cmd) + le32_to_cpu(cmd->hdr.length);
	struct iwl_trans *trans = prod->trans;
	u32 cmd_id = le32_to_cpu(cmd->id);
	int ret;

	if (!iwl_trans_fw_running(trans))
		return -EIO;

	if (cmd_size > max_cmd_size) {
		IWL_ERR(trans, "Smart Tester cmd is too big (%d/%d)\n",
			max_cmd_size, cmd_size);
		return -EINVAL;
	}

	/* call this to verify the command is known to firmware */
	ret = iwl_smart_tester_get_cmd_timeout(prod, cmd_id);
	if (ret < 0) {
		IWL_ERR(trans,
			"Failed to get cmd/rsp id=0x%x timeout value\n",
			cmd_id);
		return ret;
	}

	IWL_DEBUG_FW(trans, "Sending smart tester cmd id=0x%x\n", cmd_id);

	/* write the command to HW SMEM */
	ret = iwl_trans_write_mem(trans, cmd_addr, cmd, cmd_size);
	if (ret) {
		IWL_ERR(trans, "Failed to send smart tester cmd id=0x%x\n",
			ret);
		return ret;
	}

	/* inform firmware that a new command is ready */
	iwl_write_umac_prph(trans, UREG_DOORBELL_TO_ISR6,
			    UREG_DOORBELL_TO_ISR6_SMART_TESTER_CMD);

	ret = iwl_smart_tester_wait_for_rsp(prod, cmd_id);
	if (ret)
		return ret;

	return 0;
}

void iwl_smart_tester_dump_error(struct iwl_prod *prod, bool *is_valid_err)
{
	u32 err_addr = le32_to_cpu(prod->fw->smart_tester.smem.err_addr);
	u32 err_size = le32_to_cpu(prod->fw->smart_tester.smem.err_size);
	u32 err_hdr_size = sizeof(struct iwl_smart_tester_err);
	struct iwl_trans *trans = prod->trans;
	u32 err_data_size;
	struct iwl_smart_tester_err *err_buf;
	u32 i;

	/* allocate max err_buf_size */
	err_buf = kmalloc(err_size, GFP_KERNEL);
	if (!err_buf) {
		IWL_ERR(trans,
			"Failed to allocate HW SMEM error table (size %d)\n",
			err_size);
		return;
	}

	/* first read the error header to check if the error buffer is valid
	 * and get the actual error size
	 */
	iwl_trans_read_mem_bytes(trans, err_addr, err_buf, err_hdr_size);

	if (le32_to_cpu(err_buf->hdr.is_valid) != SMART_TESTER_BUF_IS_VALID) {
		IWL_DEBUG_FW(trans,
			     "Skip Smart Tester error log (is_valid=0x%x)\n",
			      le32_to_cpu(err_buf->hdr.is_valid));
		goto out;
	}

	/* as checked above */
	if (is_valid_err)
		*is_valid_err = true;

	/* print header */
	IWL_ERR(trans, "Start Smart Tester HW SMEM Error Log Dump:\n");
	IWL_ERR(trans,
		"0x%08x | is_valid\n", le32_to_cpu(err_buf->hdr.is_valid));
	IWL_ERR(trans,
		"0x%08x | length\n", le32_to_cpu(err_buf->hdr.length));
	IWL_ERR(trans,
		"0x%08x | ver_id\n", le32_to_cpu(err_buf->hdr.ver_id));
	IWL_ERR(trans,
		"0x%08x | err_id\n", le32_to_cpu(err_buf->err_id));

	if (!err_buf->hdr.length)
		goto out;

	/* truncate hdr.length (after converting from dwords to bytes) if it
	 * exceeds the expected maximum error data length (already in bytes)
	 */
	err_data_size = min(le32_to_cpu(err_buf->hdr.length) << 2,
			    err_size - err_hdr_size);
	iwl_trans_read_mem_bytes(trans, err_addr + err_hdr_size,
				 &err_buf->data, err_data_size);

	/* TODO: currently just dump the data as is without any real parsing.
	 * check if we need similar parsing to iwl_fwrt_dump_error_logs()
	 */
	for (i = 0; i < err_data_size >> 2; i++)
		IWL_ERR(trans, "0x%08x | error data (offset 0x%04lx)\n",
			le32_to_cpu(err_buf->data[i]), i * sizeof(u32));

out:
	kfree(err_buf);
}

/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 - 2017        Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019        Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 - 2017        Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019        Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/debugfs.h>
#include <net/cfg80211.h>
#include "fmac.h"
#include "iwl-io.h"

#define FMAC_DEBUGFS_OPEN_WRAPPER(name, buflen, argtype)		\
struct dbgfs_##name##_data {						\
	argtype *arg;							\
	bool read_done;							\
	ssize_t rlen;							\
	char rbuf[buflen];						\
};									\
static int _iwl_dbgfs_##name##_open(struct inode *inode,		\
				    struct file *file)			\
{									\
	struct dbgfs_##name##_data *data;				\
									\
	data = kzalloc(sizeof(*data), GFP_KERNEL);			\
	if (!data)							\
		return -ENOMEM;						\
									\
	data->read_done = false;					\
	data->arg = inode->i_private;					\
	file->private_data = data;					\
									\
	return 0;							\
}

#define FMAC_DEBUGFS_READ_WRAPPER(name)					\
static ssize_t _iwl_dbgfs_##name##_read(struct file *file,		\
					char __user *user_buf,		\
					size_t count, loff_t *ppos)	\
{									\
	struct dbgfs_##name##_data *data = file->private_data;		\
									\
	if (!data->read_done) {						\
		data->read_done = true;					\
		data->rlen = iwl_dbgfs_##name##_read(data->arg,		\
						     sizeof(data->rbuf),\
						     data->rbuf);	\
	}								\
									\
	if (data->rlen < 0)						\
		return data->rlen;					\
	return simple_read_from_buffer(user_buf, count, ppos,		\
				       data->rbuf, data->rlen);		\
}

static int _iwl_dbgfs_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);

	return 0;
}

#define _FMAC_DEBUGFS_READ_FILE_OPS(name, buflen, argtype)		\
FMAC_DEBUGFS_OPEN_WRAPPER(name, buflen, argtype)			\
FMAC_DEBUGFS_READ_WRAPPER(name)						\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.read = _iwl_dbgfs_##name##_read,				\
	.open = _iwl_dbgfs_##name##_open,				\
	.llseek = generic_file_llseek,					\
	.release = _iwl_dbgfs_release,					\
}

#define FMAC_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)		\
static ssize_t _iwl_dbgfs_##name##_write(struct file *file,		\
					 const char __user *user_buf,	\
					 size_t count, loff_t *ppos)	\
{									\
	argtype *arg =							\
		((struct dbgfs_##name##_data *)file->private_data)->arg;\
	char buf[buflen] = {};						\
	size_t buf_size = min(count, sizeof(buf) -  1);			\
									\
	if (copy_from_user(buf, user_buf, buf_size))			\
		return -EFAULT;						\
									\
	return iwl_dbgfs_##name##_write(arg, buf, buf_size);		\
}

#define _FMAC_DEBUGFS_READ_WRITE_FILE_OPS(name, buflen, argtype)	\
FMAC_DEBUGFS_OPEN_WRAPPER(name, buflen, argtype)			\
FMAC_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)			\
FMAC_DEBUGFS_READ_WRAPPER(name)						\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write = _iwl_dbgfs_##name##_write,				\
	.read = _iwl_dbgfs_##name##_read,				\
	.open = _iwl_dbgfs_##name##_open,				\
	.llseek = generic_file_llseek,					\
	.release = _iwl_dbgfs_release,					\
}

#define _FMAC_DEBUGFS_WRITE_FILE_OPS(name, buflen, argtype)		\
FMAC_DEBUGFS_OPEN_WRAPPER(name, buflen, argtype)			\
FMAC_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)			\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write = _iwl_dbgfs_##name##_write,				\
	.open = _iwl_dbgfs_##name##_open,				\
	.llseek = generic_file_llseek,					\
	.release = _iwl_dbgfs_release,					\
}

#define FMAC_DEBUGFS_READ_FILE_OPS(name, bufsz)				\
	_FMAC_DEBUGFS_READ_FILE_OPS(name, bufsz, struct iwl_fmac)

#define FMAC_DEBUGFS_WRITE_FILE_OPS(name, bufsz)			\
	_FMAC_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct iwl_fmac)

#define FMAC_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz)			\
	_FMAC_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz, struct iwl_fmac)

#define FMAC_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode)		\
	debugfs_create_file(alias, mode, parent, fmac,			\
			    &iwl_dbgfs_##name##_ops)			\

#define FMAC_DEBUGFS_ADD_FILE(name, mode)				\
	FMAC_DEBUGFS_ADD_FILE_ALIAS(#name, name, fmac->dbgfs_dir, mode)

static ssize_t iwl_dbgfs_intcmd_dbg_read(struct iwl_fmac *fmac, size_t size,
					 char *buf)
{
	return scnprintf(buf, size, "%d\n", fmac->internal_cmd_to_host);
}

static ssize_t iwl_dbgfs_intcmd_dbg_write(struct iwl_fmac *fmac,
					  char *buf, size_t count)
{
	u8 v;
	int ret;

	ret = kstrtou8(buf, 0, &v);
	if (ret)
		return ret;

	mutex_lock(&fmac->mutex);

	fmac->internal_cmd_to_host = v;

	if (iwl_fmac_firmware_running(fmac))
		ret = iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
					IWL_FMAC_CONFIG_INTERNAL_CMD_TO_HOST,
					fmac->internal_cmd_to_host);
	else
		ret = -EIO;

	mutex_unlock(&fmac->mutex);

	return ret ?: count;
}

FMAC_DEBUGFS_READ_WRITE_FILE_OPS(intcmd_dbg, 4);

static ssize_t iwl_dbgfs_fw_nmi_write(struct iwl_fmac *fmac,
				      char *buf, size_t count)
{
	iwl_force_nmi(fmac->trans);

	return count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(fw_nmi, 4);

static ssize_t iwl_dbgfs_debug_level_read(struct iwl_fmac *fmac, size_t size,
					  char *buf)
{
	return scnprintf(buf, size, "%d\n", fmac->fw_debug_level);
}

static ssize_t iwl_dbgfs_debug_level_write(struct iwl_fmac *fmac,
					   char *buf, size_t count)
{
	u8 v;
	int ret;

	ret = kstrtou8(buf, 0, &v);
	if (ret)
		return ret;

	mutex_lock(&fmac->mutex);

	fmac->fw_debug_level = v;

	if (iwl_fmac_firmware_running(fmac))
		ret = iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
					       IWL_FMAC_CONFIG_DEBUG_LEVEL,
					       fmac->fw_debug_level);
	else
		ret = -EIO;

	mutex_unlock(&fmac->mutex);

	return ret ?: count;
}

FMAC_DEBUGFS_READ_WRITE_FILE_OPS(debug_level, 4);

static ssize_t iwl_dbgfs_scan_type_write(struct iwl_fmac *fmac,
					 char *buf, size_t count)
{
	u8 v;
	int ret;

	ret = kstrtou8(buf, 0, &v);
	if (ret)
		return ret;

	if (v >= IWL_SCAN_TYPE_MAX)
		return -EINVAL;

	mutex_lock(&fmac->mutex);

	if (iwl_fmac_firmware_running(fmac))
		ret = iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
					       IWL_FMAC_CONFIG_SCAN_TYPE,
					       v);
	else
		ret = -EIO;

	mutex_unlock(&fmac->mutex);

	return ret ?: count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(scan_type, 4);

static ssize_t iwl_dbgfs_fw_dbg_collect_write(struct iwl_fmac *fmac,
					      char *buf, size_t count)
{
	iwl_dbg_tlv_time_point(&fmac->fwrt, IWL_FW_INI_TIME_POINT_USER_TRIGGER,
			       NULL);

	iwl_fw_dbg_collect(&fmac->fwrt, FW_DBG_TRIGGER_USER, buf,
			   (count - 1), NULL);

	return count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(fw_dbg_collect, 64);

#ifdef CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED
static ssize_t iwl_dbgfs_debug_profile_write(struct iwl_fmac *fmac,
					     char *buf, size_t count)
{
	struct iwl_dhc_cmd *dhc_cmd;
	struct iwl_dhc_profile_cmd *profile_cmd;
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(DEBUG_HOST_COMMAND, IWL_ALWAYS_LONG_GROUP, 0),
	};
	int ret;
	u32 report, reset, period, metrics;

	if (sscanf(buf, "%x,%x,%x,%x", &report, &reset, &period,
		   &metrics) != 4)
		return -EINVAL;

	/* allocate the maximal amount of memory that can be sent */
	dhc_cmd = kzalloc(sizeof(*dhc_cmd) + sizeof(*profile_cmd), GFP_KERNEL);
	if (!dhc_cmd)
		return -ENOMEM;

	hcmd.len[0] = sizeof(*dhc_cmd);
	if (report) {
		dhc_cmd->length = cpu_to_le32(sizeof(reset) >> 2);
		dhc_cmd->index_and_mask =
			cpu_to_le32(DHC_TABLE_AUTOMATION | DHC_TARGET_UMAC |
				    DHC_AUTO_UMAC_REPORT_PROFILING);
		dhc_cmd->data[0] = cpu_to_le32(reset);
		hcmd.len[0] += sizeof(reset);
	} else {
		dhc_cmd->length = cpu_to_le32(sizeof(*profile_cmd) >> 2);
		dhc_cmd->index_and_mask =
			cpu_to_le32(DHC_TABLE_AUTOMATION | DHC_TARGET_UMAC |
				    DHC_AUTO_UMAC_SET_PROFILING_REPORT_CONF);

		profile_cmd = (void *)dhc_cmd->data;
		profile_cmd->reset = cpu_to_le32(reset);
		profile_cmd->period = cpu_to_le32(period);
		profile_cmd->enabled_metrics = cpu_to_le32(metrics);
		hcmd.len[0] += sizeof(*profile_cmd);
	}
	hcmd.data[0] = dhc_cmd;
	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	if (ret)
		IWL_ERR(fmac, "failed to send DHC profiling cmd\n");
	mutex_unlock(&fmac->mutex);
	kfree(dhc_cmd);

	return ret ?: count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(debug_profile, 64);
#endif /* CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED */

/* configure low latency
 * the location is stations/<mac addr>, this is also the reason it
 * cannot use the standard macros for creating debugfs API
 */
static ssize_t iwl_dbgfs_low_latency_write(struct file *file,
					   const char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct iwl_fmac_sta *sta = file->private_data;
	struct iwl_fmac_vif *vif = sta->vif;
	struct iwl_fmac *fmac = vif->fmac;
	bool low_latency;
	int ret;

	ret = kstrtobool_from_user(user_buf, count, &low_latency);
	if (ret)
		return ret;

	mutex_lock(&fmac->mutex);

	if (iwl_fmac_firmware_running(fmac))
		ret = iwl_fmac_send_config_u32(fmac, vif->id,
					       IWL_FMAC_CONFIG_VIF_LOW_LATENCY,
					       low_latency);
	else
		ret = -EIO;

	mutex_unlock(&fmac->mutex);

	IWL_DEBUG_RATE(fmac, "set low latency to %d for vif id %d\n",
		       low_latency, vif->id);

	return ret ?: count;
}

static const struct file_operations iwl_dbgfs_low_latency_ops = {
	.write = iwl_dbgfs_low_latency_write,
	.open = simple_open,
	.llseek = generic_file_llseek,
};

#ifdef CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED
/*
 * handle fixed rate table for TLC
 * the location is stations/<mac addr>, this is also the reason it
 * cannot use the standard macros for creating debugfs API
 */
static ssize_t iwl_dbgfs_rs_table_write(struct file *file,
					const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct iwl_fmac_sta *sta = file->private_data;
	struct iwl_fmac *fmac;
	struct iwl_dhc_cmd *dhc_cmd;
	struct iwl_dhc_tlc_cmd *dhc_tlc_cmd;
	u32 cmd_id = iwl_cmd_id(DEBUG_HOST_COMMAND, IWL_ALWAYS_LONG_GROUP, 0);
	u32 hw_rate;
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0, &hw_rate);
	if (ret)
		return ret;

	dhc_cmd = kzalloc(sizeof(*dhc_cmd) + sizeof(*dhc_tlc_cmd), GFP_KERNEL);
	if (!dhc_cmd)
		return -ENOMEM;

	fmac = sta->vif->fmac;

	IWL_DEBUG_RATE(fmac, "sta_id %d rate 0x%X\n", sta->sta_id, hw_rate);

	dhc_tlc_cmd = (void *)dhc_cmd->data;
	dhc_tlc_cmd->sta_id = sta->sta_id;
	dhc_tlc_cmd->data[0] = cpu_to_le32(hw_rate);
	dhc_tlc_cmd->type = cpu_to_le32(IWL_TLC_DEBUG_FIXED_RATE);
	dhc_cmd->length = cpu_to_le32(sizeof(*dhc_tlc_cmd) >> 2);
	dhc_cmd->index_and_mask =
		cpu_to_le32(DHC_TABLE_INTEGRATION | DHC_TARGET_UMAC |
			    DHC_INTEGRATION_TLC_DEBUG_CONFIG);

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd_pdu(fmac, cmd_id, 0,
				    sizeof(*dhc_cmd) + sizeof(*dhc_tlc_cmd),
				    dhc_cmd);
	mutex_unlock(&fmac->mutex);
	if (ret)
		IWL_ERR(fmac, "Failed to send TLC Debug command: %d\n", ret);

	kfree(dhc_cmd);
	return ret ?: count;
}

static int iwl_rs_set_ampdu_size(struct iwl_fmac *fmac,
				 struct iwl_fmac_sta *sta, u32 agg_limit)
{
	struct iwl_dhc_cmd *dhc_cmd;
	struct iwl_dhc_tlc_cmd *dhc_tlc_cmd;
	u32 cmd_id = iwl_cmd_id(DEBUG_HOST_COMMAND, IWL_ALWAYS_LONG_GROUP, 0);
	int ret;

	dhc_cmd = kzalloc(sizeof(*dhc_cmd) + sizeof(*dhc_tlc_cmd), GFP_KERNEL);
	if (!dhc_cmd)
		return -ENOMEM;

	IWL_DEBUG_RATE(fmac, "sta_id %d agg_frame__lim %d\n", sta->sta_id,
		       agg_limit);

	dhc_tlc_cmd = (void *)dhc_cmd->data;
	dhc_tlc_cmd->sta_id = sta->sta_id;
	dhc_tlc_cmd->data[0] = cpu_to_le32(agg_limit);
	dhc_tlc_cmd->type = cpu_to_le32(IWL_TLC_DEBUG_AGG_FRAME_CNT_LIM);
	dhc_cmd->length = cpu_to_le32(sizeof(*dhc_tlc_cmd) >> 2);
	dhc_cmd->index_and_mask =
		cpu_to_le32(DHC_TABLE_INTEGRATION | DHC_TARGET_UMAC |
			    DHC_INTEGRATION_TLC_DEBUG_CONFIG);

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd_pdu(fmac, cmd_id, 0,
				    sizeof(*dhc_cmd) + sizeof(*dhc_tlc_cmd),
				    dhc_cmd);
	mutex_unlock(&fmac->mutex);
	if (ret)
		IWL_ERR(fmac, "Failed to send TLC Debug command: %d\n", ret);

	kfree(dhc_cmd);
	return 0;
}

/* handle AMPDU start and stop
 * the location is stations/<mac addr>, this is also the reason it
 * cannot use the standard macros for creating debugfs API
 */
static ssize_t iwl_dbgfs_ampdu_write(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct iwl_fmac_sta *sta = file->private_data;
	u32 agg_limit;
	int ret;

	if (kstrtou32_from_user(user_buf, count, 0, &agg_limit))
		agg_limit = 0;

	ret = iwl_rs_set_ampdu_size(sta->vif->fmac, sta, agg_limit);

	return ret ?: count;
}

static const struct file_operations iwl_dbgfs_ampdu_ops = {
	.write = iwl_dbgfs_ampdu_write,
	.open = simple_open,
	.llseek = generic_file_llseek,
};

static const struct file_operations iwl_dbgfs_rs_table_ops = {
	.write = iwl_dbgfs_rs_table_write,
	.open = simple_open,
	.llseek = generic_file_llseek,
};

#endif

void iwl_fmac_dbgfs_add_sta(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta)
{
	u8 mac[3 * ETH_ALEN];

	if (!sta || !fmac->dbgfs_dir || !fmac->dbgfs_dir_stations)
		return;

	snprintf(mac, sizeof(mac), "%pM", sta->addr);

	sta->dbgfs_dir = debugfs_create_dir(mac, fmac->dbgfs_dir_stations);
	if (!sta->dbgfs_dir)
		return;

	debugfs_create_file("low_latency", S_IWUSR, sta->dbgfs_dir,
			    sta, &iwl_dbgfs_low_latency_ops);

#ifdef CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED
	debugfs_create_file("rate_scale_table", S_IWUSR, sta->dbgfs_dir,
			    sta, &iwl_dbgfs_rs_table_ops);

	debugfs_create_file("ampdu", S_IWUSR, sta->dbgfs_dir,
				    sta, &iwl_dbgfs_ampdu_ops);
#endif /* CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED */
}

void iwl_fmac_dbgfs_del_sta(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta)
{
	if (sta && sta->dbgfs_dir && fmac->dbgfs_dir) {
		debugfs_remove_recursive(sta->dbgfs_dir);
		sta->dbgfs_dir = NULL;
	}
}

static ssize_t iwl_dbgfs_mem_read(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct iwl_fmac *fmac = file->private_data;
	struct iwl_dbg_mem_access_cmd cmd = {};
	struct iwl_dbg_mem_access_rsp *rsp;
	struct iwl_host_cmd hcmd = {
		.flags = CMD_WANT_SKB | CMD_SEND_IN_RFKILL,
		.data = { &cmd, },
		.len = { sizeof(cmd) },
	};
	size_t delta;
	ssize_t len, ret;

	hcmd.id = iwl_cmd_id(*ppos >> 24 ? UMAC_RD_WR : LMAC_RD_WR,
			     DEBUG_GROUP, 0);
	cmd.op = cpu_to_le32(DEBUG_MEM_OP_READ);

	/* Take care of alignment of both the position and the length */
	delta = *ppos & 0x3;
	cmd.addr = cpu_to_le32(*ppos - delta);
	cmd.len = cpu_to_le32(min(ALIGN(count + delta, 4) / 4,
				  (size_t)DEBUG_MEM_MAX_SIZE_DWORDS));

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	mutex_unlock(&fmac->mutex);

	if (ret < 0)
		return ret;

	rsp = (void *)hcmd.resp_pkt->data;
	if (le32_to_cpu(rsp->status) != DEBUG_MEM_STATUS_SUCCESS) {
		ret = -ENXIO;
		goto out;
	}

	len = min((size_t)le32_to_cpu(rsp->len) << 2,
		  iwl_rx_packet_payload_len(hcmd.resp_pkt) - sizeof(*rsp));
	len = min_t(ssize_t, len - delta, count);
	if (len < 0) {
		ret = -EFAULT;
		goto out;
	}

	ret = len - copy_to_user(user_buf, (void *)rsp->data + delta, len);
	*ppos += ret;

out:
	iwl_free_resp(&hcmd);
	return ret;
}

static ssize_t iwl_dbgfs_mem_write(struct file *file,
				   const char __user *user_buf, size_t count,
				   loff_t *ppos)
{
	struct iwl_fmac *fmac = file->private_data;
	struct iwl_dbg_mem_access_cmd *cmd;
	struct iwl_dbg_mem_access_rsp *rsp;
	struct iwl_host_cmd hcmd = {};
	size_t cmd_size;
	size_t data_size;
	u32 op, len;
	ssize_t ret;

	hcmd.id = iwl_cmd_id(*ppos >> 24 ? UMAC_RD_WR : LMAC_RD_WR,
			     DEBUG_GROUP, 0);

	if (*ppos & 0x3 || count < 4) {
		op = DEBUG_MEM_OP_WRITE_BYTES;
		len = min(count, (size_t)(4 - (*ppos & 0x3)));
		data_size = len;
	} else {
		op = DEBUG_MEM_OP_WRITE;
		len = min(count >> 2, (size_t)DEBUG_MEM_MAX_SIZE_DWORDS);
		data_size = len << 2;
	}

	cmd_size = sizeof(*cmd) + ALIGN(data_size, 4);
	cmd = kzalloc(cmd_size, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cmd->op = cpu_to_le32(op);
	cmd->len = cpu_to_le32(len);
	cmd->addr = cpu_to_le32(*ppos);
	if (copy_from_user((void *)cmd->data, user_buf, data_size)) {
		kfree(cmd);
		return -EFAULT;
	}

	hcmd.flags = CMD_WANT_SKB | CMD_SEND_IN_RFKILL,
	hcmd.data[0] = (void *)cmd;
	hcmd.len[0] = cmd_size;

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	mutex_unlock(&fmac->mutex);

	kfree(cmd);

	if (ret < 0)
		return ret;

	rsp = (void *)hcmd.resp_pkt->data;
	if (rsp->status != DEBUG_MEM_STATUS_SUCCESS) {
		ret = -ENXIO;
		goto out;
	}

	ret = data_size;
	*ppos += ret;

out:
	iwl_free_resp(&hcmd);
	return ret;
}

static const struct file_operations iwl_dbgfs_mem_ops = {
	.read = iwl_dbgfs_mem_read,
	.write = iwl_dbgfs_mem_write,
	.open = simple_open,
	.llseek = default_llseek,
};

static ssize_t
iwl_dbgfs_send_echo_cmd_write(struct iwl_fmac *fmac, char *buf,
			      size_t count)
{
	int ret;

	mutex_lock(&fmac->mutex);
	if (iwl_fmac_firmware_running(fmac))
		ret = iwl_fmac_send_cmd_pdu(fmac, ECHO_CMD, 0, 0, NULL);
	else
		ret = -EIO;
	mutex_unlock(&fmac->mutex);

	return ret ?: count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(send_echo_cmd, 8);

static ssize_t iwl_dbgfs_ctdp_budget_read(struct iwl_fmac *fmac, size_t size,
					  char *buf)
{
	int budget;

	mutex_lock(&fmac->mutex);
	if (iwl_fmac_firmware_running(fmac) &&
	    fmac->fwrt.cur_fw_img == IWL_UCODE_REGULAR)
		budget = iwl_fmac_ctdp_command(fmac,
					       CTDP_CMD_OPERATION_REPORT, 0);
	else
		budget = -EIO;
	mutex_unlock(&fmac->mutex);

	if (budget < 0)
		return budget;

	return scnprintf(buf, size, "%d\n", budget);
}

FMAC_DEBUGFS_READ_FILE_OPS(ctdp_budget, 8);

static ssize_t iwl_dbgfs_stop_ctdp_write(struct iwl_fmac *fmac, char *buf,
					 size_t count)
{
	int ret;

	mutex_lock(&fmac->mutex);
	if (iwl_fmac_firmware_running(fmac) &&
	    fmac->fwrt.cur_fw_img == IWL_UCODE_REGULAR)
		ret = iwl_fmac_ctdp_command(fmac, CTDP_CMD_OPERATION_STOP, 0);
	else
		ret = -EIO;
	mutex_unlock(&fmac->mutex);

	return ret ?: count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(stop_ctdp, 8);

static ssize_t iwl_dbgfs_nic_temp_read(struct iwl_fmac *fmac, size_t size,
				       char *buf)
{
	int ret;
	s32 temp;

	mutex_lock(&fmac->mutex);
	if (iwl_fmac_firmware_running(fmac) &&
	    fmac->fwrt.cur_fw_img == IWL_UCODE_REGULAR)
		ret = iwl_fmac_get_temp(fmac, &temp);
	else
		ret = -EIO;
	mutex_unlock(&fmac->mutex);

	if (ret)
		return ret;

	return scnprintf(buf, size, "%d\n", temp);
}

FMAC_DEBUGFS_READ_FILE_OPS(nic_temp, 8);

static ssize_t iwl_dbgfs_force_ctkill_write(struct iwl_fmac *fmac, char *buf,
					    size_t count)
{
	int ret = 0;

	mutex_lock(&fmac->mutex);
	if (!iwl_fmac_firmware_running(fmac) ||
	    fmac->fwrt.cur_fw_img != IWL_UCODE_REGULAR)
		ret = -EIO;
	mutex_unlock(&fmac->mutex);

	if (ret)
		return ret;

	iwl_fmac_enter_ctkill(fmac);

	return count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(force_ctkill, 8);

static inline char *iwl_fmac_dbgfs_is_match(char *name, char *buf)
{
	int len = strlen(name);

	return !strncmp(name, buf, len) ? buf + len : NULL;
}

static ssize_t iwl_dbgfs_fw_restart_write(struct iwl_fmac *fmac,
					  char *buf, size_t count)
{
	mutex_lock(&fmac->mutex);

	if (!iwl_fmac_firmware_running(fmac)) {
		mutex_unlock(&fmac->mutex);
		return -EIO;
	}

	iwl_fmac_send_cmd_pdu(fmac, REPLY_ERROR, 0, 0, NULL);
	mutex_unlock(&fmac->mutex);

	return count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(fw_restart, 10);

static ssize_t iwl_dbgfs_indirection_tbl_write(struct iwl_fmac *fmac,
					       char *buf, size_t count)
{
	struct iwl_rss_config_cmd cmd = {
		.flags = cpu_to_le32(IWL_RSS_ENABLE),
		.hash_mask = IWL_RSS_HASH_TYPE_IPV4_TCP |
			     IWL_RSS_HASH_TYPE_IPV4_UDP |
			     IWL_RSS_HASH_TYPE_IPV4_PAYLOAD |
			     IWL_RSS_HASH_TYPE_IPV6_TCP |
			     IWL_RSS_HASH_TYPE_IPV6_UDP |
			     IWL_RSS_HASH_TYPE_IPV6_PAYLOAD,
	};
	int ret, i, num_repeats, nbytes = count / 2;

	ret = hex2bin(cmd.indirection_table, buf, nbytes);
	if (ret)
		return ret;

	/*
	 * The input is the redirection table, partial or full.
	 * Repeat the pattern if needed.
	 * For example, input of 01020F will be repeated 42 times,
	 * indirecting RSS hash results to queues 1, 2, 15 (skipping
	 * queues 3 - 14).
	 */
	num_repeats = ARRAY_SIZE(cmd.indirection_table) / nbytes;
	for (i = 1; i < num_repeats; i++)
		memcpy(&cmd.indirection_table[i * nbytes],
		       cmd.indirection_table, nbytes);
	/* handle cut in the middle pattern for the last places */
	memcpy(&cmd.indirection_table[i * nbytes], cmd.indirection_table,
	       ARRAY_SIZE(cmd.indirection_table) % nbytes);

	netdev_rss_key_fill(cmd.secret_key, sizeof(cmd.secret_key));

	mutex_lock(&fmac->mutex);
	if (iwl_fmac_firmware_running(fmac))
		ret = iwl_fmac_send_cmd_pdu(fmac, RSS_CONFIG_CMD, 0,
					    sizeof(cmd), &cmd);
	else
		ret = 0;
	mutex_unlock(&fmac->mutex);

	return ret ?: count;
}

FMAC_DEBUGFS_WRITE_FILE_OPS(indirection_tbl,
			    (IWL_RSS_INDIRECTION_TABLE_SIZE * 2));

void iwl_fmac_dbgfs_init(struct iwl_fmac *fmac, struct dentry *dbgfs_dir)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	char buf[100];

	fmac->dbgfs_dir = debugfs_create_dir("fmac", wiphy->debugfsdir);
	if (!fmac->dbgfs_dir)
		return;

	fmac->dbgfs_dir_stations = debugfs_create_dir("stations",
						      fmac->dbgfs_dir);
	if (!fmac->dbgfs_dir_stations)
		IWL_ERR(fmac, "dbgfs - failed to create stations sub dir\n");

	FMAC_DEBUGFS_ADD_FILE(intcmd_dbg, S_IWUSR | S_IRUSR);
	FMAC_DEBUGFS_ADD_FILE(debug_level, S_IWUSR | S_IRUSR);
	FMAC_DEBUGFS_ADD_FILE(scan_type, S_IWUSR);
	FMAC_DEBUGFS_ADD_FILE(fw_dbg_collect, S_IWUSR);
	FMAC_DEBUGFS_ADD_FILE(send_echo_cmd, S_IWUSR);
	FMAC_DEBUGFS_ADD_FILE(fw_nmi, S_IWUSR);
#ifdef CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED
	FMAC_DEBUGFS_ADD_FILE(debug_profile, S_IWUSR);
#endif /* CPTCFG_IWLWIFI_DEBUG_HOST_CMD_ENABLED */
	FMAC_DEBUGFS_ADD_FILE(ctdp_budget, S_IRUSR);
	FMAC_DEBUGFS_ADD_FILE(stop_ctdp, S_IWUSR);
	FMAC_DEBUGFS_ADD_FILE(nic_temp, S_IRUSR);
	FMAC_DEBUGFS_ADD_FILE(force_ctkill, S_IWUSR);
	FMAC_DEBUGFS_ADD_FILE(fw_restart, S_IWUSR);
	FMAC_DEBUGFS_ADD_FILE(indirection_tbl, S_IWUSR);
	debugfs_create_file("mem", S_IRUSR | S_IWUSR, fmac->dbgfs_dir, fmac,
			    &iwl_dbgfs_mem_ops);

#if LINUX_VERSION_IS_GEQ(3, 12, 0)
	snprintf(buf, 100, "../../../%pd2", dbgfs_dir->d_parent);
#else
	snprintf(buf, 100, "../../../%s/%s",
		 dbgfs_dir->d_parent->d_parent->d_name.name,
		 dbgfs_dir->d_parent->d_name.name);
#endif
	debugfs_create_symlink("iwlwifi", fmac->dbgfs_dir, buf);
}

void iwl_fmac_dbgfs_exit(struct iwl_fmac *fmac)
{
	debugfs_remove_recursive(fmac->dbgfs_dir);
	fmac->dbgfs_dir = NULL;
	fmac->dbgfs_dir_stations = NULL;
}

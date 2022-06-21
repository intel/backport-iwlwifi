// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2012-2014, 2018-2021 Intel Corporation
 * Copyright (C) 2013-2015 Intel Mobile Communications GmbH
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 */
#include <linux/vmalloc.h>
#include <linux/err.h>
#include <linux/ieee80211.h>
#include <linux/netdevice.h>

#include "mvm.h"
#include "sta.h"
#include "iwl-io.h"
#include "debugfs.h"
#include "iwl-modparams.h"
#include "fw/error-dump.h"
#ifdef CPTCFG_IWLMVM_AX_SOFTAP_TESTMODE
#include "fw/api/ax-softap-testmode.h"
#endif

#ifdef CPTCFG_IWLWIFI_THERMAL_DEBUGFS
static ssize_t iwl_dbgfs_tt_tx_backoff_write(struct iwl_mvm *mvm, char *buf,
					     size_t count, loff_t *ppos)
{
	int i = 0;
	int ret;
	u32 temperature, backoff;
	char *value_str;
	char *seps = "\n ";
	char *buf_ptr = buf;
	struct iwl_tt_tx_backoff new_backoff_values[TT_TX_BACKOFF_SIZE];

	mutex_lock(&mvm->mutex);
	while ((value_str = strsep(&buf_ptr, seps))) {
		if (sscanf(value_str, "%u=%u", &temperature, &backoff) != 2)
			break;

		if (temperature >=
		    mvm->thermal_throttle.params.ct_kill_entry ||
		    backoff < mvm->thermal_throttle.min_backoff) {
			ret = -EINVAL;
			goto out;
		}

		if (i == TT_TX_BACKOFF_SIZE) {
			ret = -EINVAL;
			goto out;
		}

		new_backoff_values[i].backoff = backoff;
		new_backoff_values[i].temperature = temperature;
		i++;
	}

	if (i != TT_TX_BACKOFF_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(mvm->thermal_throttle.params.tx_backoff, new_backoff_values,
	       sizeof(mvm->thermal_throttle.params.tx_backoff));

	ret = count;

out:
	mutex_unlock(&mvm->mutex);
	return ret;
}

static ssize_t iwl_dbgfs_tt_tx_backoff_read(struct file *file,
					    char __user *user_buf, size_t count,
					    loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct iwl_tt_tx_backoff *tx_backoff =
	       mvm->thermal_throttle.params.tx_backoff;
	/* we need 10 chars per line: 3 chars for the temperature + 1
	 * for the equal sign + 5 for the backoff value + end of line.
	*/
	char buf[TT_TX_BACKOFF_SIZE * 10 + 1];
	int i, pos = 0, bufsz = sizeof(buf);

	mutex_lock(&mvm->mutex);
	for (i = 0; i < TT_TX_BACKOFF_SIZE; i++) {
		pos += scnprintf(buf + pos, bufsz - pos, "%d=%d\n",
				 tx_backoff[i].temperature,
				 tx_backoff[i].backoff);
	}
	mutex_unlock(&mvm->mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}
#endif

static ssize_t iwl_dbgfs_ctdp_budget_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char buf[16];
	int pos, budget;

	if (!iwl_mvm_is_ctdp_supported(mvm))
		return -EOPNOTSUPP;

	if (!iwl_mvm_firmware_running(mvm) ||
	    mvm->fwrt.cur_fw_img != IWL_UCODE_REGULAR)
		return -EIO;

	mutex_lock(&mvm->mutex);
	budget = iwl_mvm_ctdp_command(mvm, CTDP_CMD_OPERATION_REPORT, 0);
	mutex_unlock(&mvm->mutex);

	if (budget < 0)
		return budget;

	pos = scnprintf(buf, sizeof(buf), "%d\n", budget);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_stop_ctdp_write(struct iwl_mvm *mvm, char *buf,
					 size_t count, loff_t *ppos)
{
	int ret;

	if (!iwl_mvm_is_ctdp_supported(mvm))
		return -EOPNOTSUPP;

	if (!iwl_mvm_firmware_running(mvm) ||
	    mvm->fwrt.cur_fw_img != IWL_UCODE_REGULAR)
		return -EIO;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_ctdp_command(mvm, CTDP_CMD_OPERATION_STOP, 0);
	mutex_unlock(&mvm->mutex);

	return ret ?: count;
}

static ssize_t iwl_dbgfs_force_ctkill_write(struct iwl_mvm *mvm, char *buf,
					    size_t count, loff_t *ppos)
{
	if (!iwl_mvm_firmware_running(mvm) ||
	    mvm->fwrt.cur_fw_img != IWL_UCODE_REGULAR)
		return -EIO;

	iwl_mvm_enter_ctkill(mvm);

	return count;
}

static ssize_t iwl_dbgfs_tx_flush_write(struct iwl_mvm *mvm, char *buf,
					size_t count, loff_t *ppos)
{
	int ret;
	u32 flush_arg;

	if (!iwl_mvm_firmware_running(mvm) ||
	    mvm->fwrt.cur_fw_img != IWL_UCODE_REGULAR)
		return -EIO;

	if (kstrtou32(buf, 0, &flush_arg))
		return -EINVAL;

	if (iwl_mvm_has_new_tx_api(mvm)) {
		IWL_DEBUG_TX_QUEUES(mvm,
				    "FLUSHING all tids queues on sta_id = %d\n",
				    flush_arg);
		mutex_lock(&mvm->mutex);
		ret = iwl_mvm_flush_sta_tids(mvm, flush_arg, 0xFFFF)
			? : count;
		mutex_unlock(&mvm->mutex);
		return ret;
	}

	IWL_DEBUG_TX_QUEUES(mvm, "FLUSHING queues mask to flush = 0x%x\n",
			    flush_arg);

	mutex_lock(&mvm->mutex);
	ret =  iwl_mvm_flush_tx_path(mvm, flush_arg) ? : count;
	mutex_unlock(&mvm->mutex);

	return ret;
}

static ssize_t iwl_dbgfs_sta_drain_write(struct iwl_mvm *mvm, char *buf,
					 size_t count, loff_t *ppos)
{
	struct iwl_mvm_sta *mvmsta;
	int sta_id, drain, ret;

	if (!iwl_mvm_firmware_running(mvm) ||
	    mvm->fwrt.cur_fw_img != IWL_UCODE_REGULAR)
		return -EIO;

	if (sscanf(buf, "%d %d", &sta_id, &drain) != 2)
		return -EINVAL;
	if (sta_id < 0 || sta_id >= mvm->fw->ucode_capa.num_stations)
		return -EINVAL;
	if (drain < 0 || drain > 1)
		return -EINVAL;

	mutex_lock(&mvm->mutex);

	mvmsta = iwl_mvm_sta_from_staid_protected(mvm, sta_id);

	if (!mvmsta)
		ret = -ENOENT;
	else
		ret = iwl_mvm_drain_sta(mvm, mvmsta, drain) ? : count;

	mutex_unlock(&mvm->mutex);

	return ret;
}

static ssize_t iwl_dbgfs_sram_read(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	const struct fw_img *img;
	unsigned int ofs, len;
	size_t ret;
	u8 *ptr;

	if (!iwl_mvm_firmware_running(mvm))
		return -EINVAL;

	/* default is to dump the entire data segment */
	img = &mvm->fw->img[mvm->fwrt.cur_fw_img];
	ofs = img->sec[IWL_UCODE_SECTION_DATA].offset;
	len = img->sec[IWL_UCODE_SECTION_DATA].len;

	if (mvm->dbgfs_sram_len) {
		ofs = mvm->dbgfs_sram_offset;
		len = mvm->dbgfs_sram_len;
	}

	ptr = kzalloc(len, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	iwl_trans_read_mem_bytes(mvm->trans, ofs, ptr, len);

	ret = simple_read_from_buffer(user_buf, count, ppos, ptr, len);

	kfree(ptr);

	return ret;
}

static ssize_t iwl_dbgfs_sram_write(struct iwl_mvm *mvm, char *buf,
				    size_t count, loff_t *ppos)
{
	const struct fw_img *img;
	u32 offset, len;
	u32 img_offset, img_len;

	if (!iwl_mvm_firmware_running(mvm))
		return -EINVAL;

	img = &mvm->fw->img[mvm->fwrt.cur_fw_img];
	img_offset = img->sec[IWL_UCODE_SECTION_DATA].offset;
	img_len = img->sec[IWL_UCODE_SECTION_DATA].len;

	if (sscanf(buf, "%x,%x", &offset, &len) == 2) {
		if ((offset & 0x3) || (len & 0x3))
			return -EINVAL;

		if (offset + len > img_offset + img_len)
			return -EINVAL;

		mvm->dbgfs_sram_offset = offset;
		mvm->dbgfs_sram_len = len;
	} else {
		mvm->dbgfs_sram_offset = 0;
		mvm->dbgfs_sram_len = 0;
	}

	return count;
}

static ssize_t iwl_dbgfs_set_nic_temperature_read(struct file *file,
						  char __user *user_buf,
						  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char buf[16];
	int pos;

	if (!mvm->temperature_test)
		pos = scnprintf(buf , sizeof(buf), "disabled\n");
	else
		pos = scnprintf(buf , sizeof(buf), "%d\n", mvm->temperature);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

/*
 * Set NIC Temperature
 * Cause the driver to ignore the actual NIC temperature reported by the FW
 * Enable: any value between IWL_MVM_DEBUG_SET_TEMPERATURE_MIN -
 * IWL_MVM_DEBUG_SET_TEMPERATURE_MAX
 * Disable: IWL_MVM_DEBUG_SET_TEMPERATURE_DISABLE
 */
static ssize_t iwl_dbgfs_set_nic_temperature_write(struct iwl_mvm *mvm,
						   char *buf, size_t count,
						   loff_t *ppos)
{
	int temperature;

	if (!iwl_mvm_firmware_running(mvm) && !mvm->temperature_test)
		return -EIO;

	if (kstrtoint(buf, 10, &temperature))
		return -EINVAL;
	/* not a legal temperature */
	if ((temperature > IWL_MVM_DEBUG_SET_TEMPERATURE_MAX &&
	     temperature != IWL_MVM_DEBUG_SET_TEMPERATURE_DISABLE) ||
	    temperature < IWL_MVM_DEBUG_SET_TEMPERATURE_MIN)
		return -EINVAL;

	mutex_lock(&mvm->mutex);
	if (temperature == IWL_MVM_DEBUG_SET_TEMPERATURE_DISABLE) {
		if (!mvm->temperature_test)
			goto out;

		mvm->temperature_test = false;
		/* Since we can't read the temp while awake, just set
		 * it to zero until we get the next RX stats from the
		 * firmware.
		 */
		mvm->temperature = 0;
	} else {
		mvm->temperature_test = true;
		mvm->temperature = temperature;
	}
	IWL_DEBUG_TEMP(mvm, "%sabling debug set temperature (temp = %d)\n",
		       mvm->temperature_test ? "En" : "Dis" ,
		       mvm->temperature);
	/* handle the temperature change */
	iwl_mvm_tt_handler(mvm);

out:
	mutex_unlock(&mvm->mutex);

	return count;
}

static ssize_t iwl_dbgfs_nic_temp_read(struct file *file,
				       char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char buf[16];
	int pos, ret;
	s32 temp;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_get_temp(mvm, &temp);
	mutex_unlock(&mvm->mutex);

	if (ret)
		return -EIO;

	pos = scnprintf(buf , sizeof(buf), "%d\n", temp);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

#ifdef CONFIG_ACPI
static ssize_t iwl_dbgfs_sar_geo_profile_read(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char buf[256];
	int pos = 0;
	int bufsz = sizeof(buf);
	int tbl_idx;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	mutex_lock(&mvm->mutex);
	tbl_idx = iwl_mvm_get_sar_geo_profile(mvm);
	if (tbl_idx < 0) {
		mutex_unlock(&mvm->mutex);
		return tbl_idx;
	}

	if (!tbl_idx) {
		pos = scnprintf(buf, bufsz,
				"SAR geographic profile disabled\n");
	} else {
		pos += scnprintf(buf + pos, bufsz - pos,
				 "Use geographic profile %d\n", tbl_idx);
		pos += scnprintf(buf + pos, bufsz - pos,
				 "2.4GHz:\n\tChain A offset: %hhu dBm\n\tChain B offset: %hhu dBm\n\tmax tx power: %hhu dBm\n",
				 mvm->fwrt.geo_profiles[tbl_idx - 1].bands[0].chains[0],
				 mvm->fwrt.geo_profiles[tbl_idx - 1].bands[0].chains[1],
				 mvm->fwrt.geo_profiles[tbl_idx - 1].bands[0].max);
		pos += scnprintf(buf + pos, bufsz - pos,
				 "5.2GHz:\n\tChain A offset: %hhu dBm\n\tChain B offset: %hhu dBm\n\tmax tx power: %hhu dBm\n",
				 mvm->fwrt.geo_profiles[tbl_idx - 1].bands[1].chains[0],
				 mvm->fwrt.geo_profiles[tbl_idx - 1].bands[1].chains[1],
				 mvm->fwrt.geo_profiles[tbl_idx - 1].bands[1].max);
	}
	mutex_unlock(&mvm->mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}
#endif

static ssize_t iwl_dbgfs_stations_read(struct file *file, char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct ieee80211_sta *sta;
	char buf[400];
	int i, pos = 0, bufsz = sizeof(buf);

	mutex_lock(&mvm->mutex);

	for (i = 0; i < mvm->fw->ucode_capa.num_stations; i++) {
		pos += scnprintf(buf + pos, bufsz - pos, "%.2d: ", i);
		sta = rcu_dereference_protected(mvm->fw_id_to_mac_id[i],
						lockdep_is_held(&mvm->mutex));
		if (!sta)
			pos += scnprintf(buf + pos, bufsz - pos, "N/A\n");
		else if (IS_ERR(sta))
			pos += scnprintf(buf + pos, bufsz - pos, "%ld\n",
					 PTR_ERR(sta));
		else
			pos += scnprintf(buf + pos, bufsz - pos, "%pM\n",
					 sta->addr);
	}

	mutex_unlock(&mvm->mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_rs_data_read(struct file *file, char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);
	struct iwl_lq_sta_rs_fw *lq_sta = &mvmsta->lq_sta.rs_fw;
	struct iwl_mvm *mvm = lq_sta->pers.drv;
	static const size_t bufsz = 2048;
	char *buff;
	int desc = 0;
	ssize_t ret;

	buff = kmalloc(bufsz, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	mutex_lock(&mvm->mutex);

	desc += scnprintf(buff + desc, bufsz - desc, "sta_id %d\n",
			  lq_sta->pers.sta_id);
	desc += scnprintf(buff + desc, bufsz - desc,
			  "fixed rate 0x%X\n",
			  lq_sta->pers.dbg_fixed_rate);
	desc += scnprintf(buff + desc, bufsz - desc,
			  "A-MPDU size limit %d\n",
			  lq_sta->pers.dbg_agg_frame_count_lim);
	desc += scnprintf(buff + desc, bufsz - desc,
			  "valid_tx_ant %s%s\n",
		(iwl_mvm_get_valid_tx_ant(mvm) & ANT_A) ? "ANT_A," : "",
		(iwl_mvm_get_valid_tx_ant(mvm) & ANT_B) ? "ANT_B," : "");
	desc += scnprintf(buff + desc, bufsz - desc,
			  "last tx rate=0x%X ",
			  lq_sta->last_rate_n_flags);

	desc += rs_pretty_print_rate(buff + desc, bufsz - desc,
				     lq_sta->last_rate_n_flags);
	if (desc < bufsz - 1)
		buff[desc++] = '\n';
	mutex_unlock(&mvm->mutex);

	ret = simple_read_from_buffer(user_buf, count, ppos, buff, desc);
	kfree(buff);
	return ret;
}

#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
static ssize_t iwl_dbgfs_send_ps_config_dhc(struct iwl_mvm *mvm,
					    struct iwl_ps_config *ps_cfg_cmd)
{
	int ret;
	struct iwl_dhc_cmd *dhc_cmd;
	struct iwl_host_cmd hcmd = {
			.id = WIDE_ID(LEGACY_GROUP, DEBUG_HOST_COMMAND),
			};

	/* allocate the maximal amount of memory that can be sent */
	dhc_cmd = kzalloc(sizeof(*dhc_cmd) + sizeof(*ps_cfg_cmd),
			  GFP_KERNEL);
	if (!dhc_cmd)
		return -ENOMEM;

	dhc_cmd->length = cpu_to_le32(sizeof(*ps_cfg_cmd) >> 2);
	dhc_cmd->index_and_mask =
			cpu_to_le32(DHC_AUTO_UMAC_CONFIGURE_POWER_FLAGS |
				    DHC_TABLE_AUTOMATION |
				    DHC_TARGET_UMAC),

	memcpy((void *)dhc_cmd->data,
	       (void *)ps_cfg_cmd,
	       sizeof(*ps_cfg_cmd));

	hcmd.len[0] = sizeof(*ps_cfg_cmd) + sizeof(*dhc_cmd);
	hcmd.data[0] = dhc_cmd;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd(mvm, &hcmd);
	mutex_unlock(&mvm->mutex);

	return ret;
}
#endif /* CPTCFG_IWLWIFI_DHC_PRIVATE */

static void iwl_rs_set_fixed_rate(struct iwl_mvm *mvm,
				  struct iwl_lq_sta_rs_fw *lq_sta)
{
	int ret = iwl_rs_send_dhc(mvm, lq_sta->pers.sta_id,
				  IWL_TLC_DEBUG_FIXED_RATE,
				  lq_sta->pers.dbg_fixed_rate);

	char pretty_rate[100];

	if (ret) {
		lq_sta->pers.dbg_fixed_rate = 0;
		return;
	}

	rs_pretty_print_rate_v1(pretty_rate, sizeof(pretty_rate),
				lq_sta->pers.dbg_fixed_rate);
	IWL_DEBUG_RATE(mvm, "sta_id %d rate %s\n",
		       lq_sta->pers.sta_id, pretty_rate);
}

static ssize_t iwl_dbgfs_fixed_rate_write(struct ieee80211_sta *sta,
					  char *buf, size_t count,
					  loff_t *ppos)
{
	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);
	struct iwl_lq_sta_rs_fw *lq_sta = &mvmsta->lq_sta.rs_fw;
	struct iwl_mvm *mvm = lq_sta->pers.drv;
	u32 parsed_rate;

	if (kstrtou32(buf, 0, &parsed_rate))
		lq_sta->pers.dbg_fixed_rate = 0;
	else
		lq_sta->pers.dbg_fixed_rate = parsed_rate;

	iwl_rs_set_fixed_rate(mvm, lq_sta);
	return count;
}

static void iwl_rs_disable_rts(struct iwl_mvm *mvm,
			       struct iwl_lq_sta_rs_fw *lq_sta,
			       u16 sta_id, bool rts_disable)
{
	if (iwl_rs_send_dhc(mvm, lq_sta->pers.sta_id,
			    IWL_TLC_DEBUG_RTS_DISABLE,
			    rts_disable))
		return;

	IWL_DEBUG_RATE(mvm, "sta_id %d rts disable 0x%X\n",
		       sta_id, rts_disable);
}

static ssize_t iwl_dbgfs_disable_rts_write(struct ieee80211_sta *sta,
					   char *buf, size_t count,
					   loff_t *ppos)
{
	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);
	struct iwl_lq_sta_rs_fw *lq_sta = &mvmsta->lq_sta.rs_fw;
	u32 sta_id = lq_sta->pers.sta_id;
	struct iwl_mvm *mvm = lq_sta->pers.drv;
	bool disable_rts;

	if (kstrtobool(buf, &disable_rts))
		return -EINVAL;

	iwl_rs_disable_rts(mvm, lq_sta, sta_id, disable_rts);
	return count;
}

static ssize_t iwl_dbgfs_tlc_dhc_write(struct ieee80211_sta *sta,
				       char *buf, size_t count,
				       loff_t *ppos)
{
	u32 type, value;
	int ret;

	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);
	struct iwl_lq_sta_rs_fw *lq_sta = &mvmsta->lq_sta.rs_fw;
	struct iwl_mvm *mvm = lq_sta->pers.drv;

	if (sscanf(buf, "%i %i", &type, &value) != 2) {
		IWL_DEBUG_RATE(mvm, "usage <type> <value>\n");
		return -EINVAL;
	}

	ret = iwl_rs_send_dhc(mvm, lq_sta->pers.sta_id, type, value);

	if (ret)
		return -EINVAL;

	return count;
}

static ssize_t iwl_dbgfs_iwl_tlc_dhc_write(struct iwl_mvm *mvm, char *buf,
					   size_t count, loff_t *ppos)
{
	u32 sta_id, type, value;
	int ret;

	if (sscanf(buf, "%i %i %i", &sta_id, &type, &value) != 3) {
		IWL_DEBUG_RATE(mvm, "usage <sta_id> <type> <value>\n");
		return -EINVAL;
	}

	ret = iwl_rs_send_dhc(mvm, sta_id, type, value);

	if (ret)
		return -EINVAL;

	return count;
}

static ssize_t iwl_dbgfs_ampdu_size_write(struct ieee80211_sta *sta,
					  char *buf, size_t count,
					  loff_t *ppos)
{
	u32 ampdu_size;
	int err;

	err = kstrtou32(buf, 0, &ampdu_size);
	if (err)
		return err;

	iwl_rs_dhc_set_ampdu_size(sta, ampdu_size);
	return count;
}

static ssize_t iwl_dbgfs_amsdu_len_write(struct ieee80211_sta *sta,
					 char *buf, size_t count,
					 loff_t *ppos)
{
	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);
	int i;
	u16 amsdu_len;

	if (kstrtou16(buf, 0, &amsdu_len))
		return -EINVAL;

	/* only change from debug set <-> debug unset */
	if (amsdu_len && mvmsta->orig_amsdu_len)
		return -EBUSY;

	if (amsdu_len) {
		mvmsta->orig_amsdu_len = sta->max_amsdu_len;
		sta->max_amsdu_len = amsdu_len;
		for (i = 0; i < ARRAY_SIZE(sta->max_tid_amsdu_len); i++)
			sta->max_tid_amsdu_len[i] = amsdu_len;
	} else {
		sta->max_amsdu_len = mvmsta->orig_amsdu_len;
		mvmsta->orig_amsdu_len = 0;
	}
	return count;
}

static ssize_t iwl_dbgfs_amsdu_len_read(struct file *file,
					char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct ieee80211_sta *sta = file->private_data;
	struct iwl_mvm_sta *mvmsta = iwl_mvm_sta_from_mac80211(sta);

	char buf[32];
	int pos;

	pos = scnprintf(buf, sizeof(buf), "current %d ", sta->max_amsdu_len);
	pos += scnprintf(buf + pos, sizeof(buf) - pos, "stored %d\n",
			 mvmsta->orig_amsdu_len);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_disable_power_off_read(struct file *file,
						char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char buf[64];
	int bufsz = sizeof(buf);
	int pos = 0;

	pos += scnprintf(buf+pos, bufsz-pos, "disable_power_off_d0=%d\n",
			 mvm->disable_power_off);
	pos += scnprintf(buf+pos, bufsz-pos, "disable_power_off_d3=%d\n",
			 mvm->disable_power_off_d3);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_disable_power_off_write(struct iwl_mvm *mvm, char *buf,
						 size_t count, loff_t *ppos)
{
	int ret, val;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	if (!strncmp("disable_power_off_d0=", buf, 21)) {
		if (sscanf(buf + 21, "%d", &val) != 1)
			return -EINVAL;
		mvm->disable_power_off = val;
	} else if (!strncmp("disable_power_off_d3=", buf, 21)) {
		if (sscanf(buf + 21, "%d", &val) != 1)
			return -EINVAL;
		mvm->disable_power_off_d3 = val;
	} else {
		return -EINVAL;
	}

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_power_update_device(mvm);
	mutex_unlock(&mvm->mutex);

	return ret ?: count;
}

#ifdef CPTCFG_IWLMVM_AX_SOFTAP_TESTMODE
static ssize_t iwl_dbgfs_ax_softap_client_testmode_write(struct iwl_mvm *mvm,
							 char *buf,
							 size_t count,
							 loff_t *ppos)
{
	u32 status;
	int ret;
	bool is_enabled;
	struct ax_softap_client_testmode_cmd cmd;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	ret = kstrtobool(buf, &is_enabled);
	if (ret) {
		IWL_ERR(mvm, "Invalid softap client debugfs value (%d)\n", ret);
		return ret;
	}

	cmd.enable = is_enabled ? 1 : 0;

	mutex_lock(&mvm->mutex);

	ret = iwl_mvm_send_cmd_pdu_status(mvm,
					  WIDE_ID(DATA_PATH_GROUP, AX_SOFTAP_CLIENT_TESTMODE),
					  sizeof(cmd), &cmd, &status);

	mutex_unlock(&mvm->mutex);

	if (ret) {
		IWL_ERR(mvm, "Failed to send softap client cmd (%d)\n", ret);
		return ret;
	}

	if (status) {
		IWL_ERR(mvm, "softap client cmd failed (%d)\n", status);
		return -EIO;
	}

	mvm->is_bar_enabled = cmd.enable ? false : true;

	return count;
}
#endif

static
int iwl_mvm_coex_dump_mbox(struct iwl_bt_coex_profile_notif *notif, char *buf,
			   int pos, int bufsz)
{
	pos += scnprintf(buf+pos, bufsz-pos, "MBOX dw0:\n");

	BT_MBOX_PRINT(0, LE_SLAVE_LAT, false);
	BT_MBOX_PRINT(0, LE_PROF1, false);
	BT_MBOX_PRINT(0, LE_PROF2, false);
	BT_MBOX_PRINT(0, LE_PROF_OTHER, false);
	BT_MBOX_PRINT(0, CHL_SEQ_N, false);
	BT_MBOX_PRINT(0, INBAND_S, false);
	BT_MBOX_PRINT(0, LE_MIN_RSSI, false);
	BT_MBOX_PRINT(0, LE_SCAN, false);
	BT_MBOX_PRINT(0, LE_ADV, false);
	BT_MBOX_PRINT(0, LE_MAX_TX_POWER, false);
	BT_MBOX_PRINT(0, OPEN_CON_1, true);

	pos += scnprintf(buf+pos, bufsz-pos, "MBOX dw1:\n");

	BT_MBOX_PRINT(1, BR_MAX_TX_POWER, false);
	BT_MBOX_PRINT(1, IP_SR, false);
	BT_MBOX_PRINT(1, LE_MSTR, false);
	BT_MBOX_PRINT(1, AGGR_TRFC_LD, false);
	BT_MBOX_PRINT(1, MSG_TYPE, false);
	BT_MBOX_PRINT(1, SSN, true);

	pos += scnprintf(buf+pos, bufsz-pos, "MBOX dw2:\n");

	BT_MBOX_PRINT(2, SNIFF_ACT, false);
	BT_MBOX_PRINT(2, PAG, false);
	BT_MBOX_PRINT(2, INQUIRY, false);
	BT_MBOX_PRINT(2, CONN, false);
	BT_MBOX_PRINT(2, SNIFF_INTERVAL, false);
	BT_MBOX_PRINT(2, DISC, false);
	BT_MBOX_PRINT(2, SCO_TX_ACT, false);
	BT_MBOX_PRINT(2, SCO_RX_ACT, false);
	BT_MBOX_PRINT(2, ESCO_RE_TX, false);
	BT_MBOX_PRINT(2, SCO_DURATION, true);

	pos += scnprintf(buf+pos, bufsz-pos, "MBOX dw3:\n");

	BT_MBOX_PRINT(3, SCO_STATE, false);
	BT_MBOX_PRINT(3, SNIFF_STATE, false);
	BT_MBOX_PRINT(3, A2DP_STATE, false);
	BT_MBOX_PRINT(3, A2DP_SRC, false);
	BT_MBOX_PRINT(3, ACL_STATE, false);
	BT_MBOX_PRINT(3, MSTR_STATE, false);
	BT_MBOX_PRINT(3, OBX_STATE, false);
	BT_MBOX_PRINT(3, OPEN_CON_2, false);
	BT_MBOX_PRINT(3, TRAFFIC_LOAD, false);
	BT_MBOX_PRINT(3, CHL_SEQN_LSB, false);
	BT_MBOX_PRINT(3, INBAND_P, false);
	BT_MBOX_PRINT(3, MSG_TYPE_2, false);
	BT_MBOX_PRINT(3, SSN_2, false);
	BT_MBOX_PRINT(3, UPDATE_REQUEST, true);

	return pos;
}

static ssize_t iwl_dbgfs_bt_notif_read(struct file *file, char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct iwl_bt_coex_profile_notif *notif = &mvm->last_bt_notif;
	char *buf;
	int ret, pos = 0, bufsz = sizeof(char) * 1024;

	buf = kmalloc(bufsz, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&mvm->mutex);

	pos += iwl_mvm_coex_dump_mbox(notif, buf, pos, bufsz);

	pos += scnprintf(buf + pos, bufsz - pos, "bt_ci_compliance = %d\n",
			 notif->bt_ci_compliance);
	pos += scnprintf(buf + pos, bufsz - pos, "primary_ch_lut = %d\n",
			 le32_to_cpu(notif->primary_ch_lut));
	pos += scnprintf(buf + pos, bufsz - pos, "secondary_ch_lut = %d\n",
			 le32_to_cpu(notif->secondary_ch_lut));
	pos += scnprintf(buf + pos,
			 bufsz - pos, "bt_activity_grading = %d\n",
			 le32_to_cpu(notif->bt_activity_grading));
	pos += scnprintf(buf + pos, bufsz - pos, "bt_rrc = %d\n",
			 notif->rrc_status & 0xF);
	pos += scnprintf(buf + pos, bufsz - pos, "bt_ttc = %d\n",
			 notif->ttc_status & 0xF);

	pos += scnprintf(buf + pos, bufsz - pos, "sync_sco = %d\n",
			 IWL_MVM_BT_COEX_SYNC2SCO);
	pos += scnprintf(buf + pos, bufsz - pos, "mplut = %d\n",
			 IWL_MVM_BT_COEX_MPLUT);

	mutex_unlock(&mvm->mutex);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, pos);
	kfree(buf);

	return ret;
}
#undef BT_MBOX_PRINT

static ssize_t iwl_dbgfs_bt_cmd_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct iwl_bt_coex_ci_cmd *cmd = &mvm->last_bt_ci_cmd;
	char buf[256];
	int bufsz = sizeof(buf);
	int pos = 0;

	mutex_lock(&mvm->mutex);

	pos += scnprintf(buf + pos, bufsz - pos, "Channel inhibition CMD\n");
	pos += scnprintf(buf + pos, bufsz - pos,
			 "\tPrimary Channel Bitmap 0x%016llx\n",
			 le64_to_cpu(cmd->bt_primary_ci));
	pos += scnprintf(buf + pos, bufsz - pos,
			 "\tSecondary Channel Bitmap 0x%016llx\n",
			 le64_to_cpu(cmd->bt_secondary_ci));

	mutex_unlock(&mvm->mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t
iwl_dbgfs_bt_tx_prio_write(struct iwl_mvm *mvm, char *buf,
			   size_t count, loff_t *ppos)
{
	u32 bt_tx_prio;

	if (sscanf(buf, "%u", &bt_tx_prio) != 1)
		return -EINVAL;
	if (bt_tx_prio > 4)
		return -EINVAL;

	mvm->bt_tx_prio = bt_tx_prio;

	return count;
}

static ssize_t
iwl_dbgfs_bt_force_ant_write(struct iwl_mvm *mvm, char *buf,
			     size_t count, loff_t *ppos)
{
	static const char * const modes_str[BT_FORCE_ANT_MAX] = {
		[BT_FORCE_ANT_DIS] = "dis",
		[BT_FORCE_ANT_AUTO] = "auto",
		[BT_FORCE_ANT_BT] = "bt",
		[BT_FORCE_ANT_WIFI] = "wifi",
	};
	int ret, bt_force_ant_mode;

	ret = match_string(modes_str, ARRAY_SIZE(modes_str), buf);
	if (ret < 0)
		return ret;

	bt_force_ant_mode = ret;
	ret = 0;
	mutex_lock(&mvm->mutex);
	if (mvm->bt_force_ant_mode == bt_force_ant_mode)
		goto out;

	mvm->bt_force_ant_mode = bt_force_ant_mode;
	IWL_DEBUG_COEX(mvm, "Force mode: %s\n",
		       modes_str[mvm->bt_force_ant_mode]);

	if (iwl_mvm_firmware_running(mvm))
		ret = iwl_mvm_send_bt_init_conf(mvm);
	else
		ret = 0;

out:
	mutex_unlock(&mvm->mutex);
	return ret ?: count;
}

static ssize_t iwl_dbgfs_fw_ver_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char *buff, *pos, *endpos;
	static const size_t bufsz = 1024;
	int ret;

	buff = kmalloc(bufsz, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	pos = buff;
	endpos = pos + bufsz;

	pos += scnprintf(pos, endpos - pos, "FW prefix: %s\n",
			 mvm->trans->cfg->fw_name_pre);
	pos += scnprintf(pos, endpos - pos, "FW: %s\n",
			 mvm->fwrt.fw->human_readable);
	pos += scnprintf(pos, endpos - pos, "Device: %s\n",
			 mvm->fwrt.trans->name);
	pos += scnprintf(pos, endpos - pos, "Bus: %s\n",
			 mvm->fwrt.dev->bus->name);

	ret = simple_read_from_buffer(user_buf, count, ppos, buff, pos - buff);
	kfree(buff);

	return ret;
}

static ssize_t iwl_dbgfs_phy_integration_ver_read(struct file *file,
						  char __user *user_buf,
						  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char *buf;
	size_t bufsz;
	int pos;
	ssize_t ret;

	bufsz = mvm->fw->phy_integration_ver_len + 2;
	buf = kmalloc(bufsz, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos = scnprintf(buf, bufsz, "%.*s\n", mvm->fw->phy_integration_ver_len,
			mvm->fw->phy_integration_ver);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, pos);

	kfree(buf);
	return ret;
}

#define PRINT_STATS_LE32(_struct, _memb)				\
			 pos += scnprintf(buf + pos, bufsz - pos,	\
					  fmt_table, #_memb,		\
					  le32_to_cpu(_struct->_memb))

static ssize_t iwl_dbgfs_fw_rx_stats_read(struct file *file,
					  char __user *user_buf, size_t count,
					  loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	static const char *fmt_table = "\t%-30s %10u\n";
	static const char *fmt_header = "%-32s\n";
	int pos = 0;
	char *buf;
	int ret;
	size_t bufsz;

	if (iwl_mvm_has_new_rx_stats_api(mvm))
		bufsz = ((sizeof(struct mvm_statistics_rx) /
			  sizeof(__le32)) * 43) + (4 * 33) + 1;
	else
		/* 43 = size of each data line; 33 = size of each header */
		bufsz = ((sizeof(struct mvm_statistics_rx_v3) /
			  sizeof(__le32)) * 43) + (4 * 33) + 1;

	buf = kzalloc(bufsz, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&mvm->mutex);

	if (iwl_mvm_firmware_running(mvm))
		iwl_mvm_request_statistics(mvm, false);

	pos += scnprintf(buf + pos, bufsz - pos, fmt_header,
			 "Statistics_Rx - OFDM");
	if (!iwl_mvm_has_new_rx_stats_api(mvm)) {
		struct mvm_statistics_rx_phy_v2 *ofdm = &mvm->rx_stats_v3.ofdm;

		PRINT_STATS_LE32(ofdm, ina_cnt);
		PRINT_STATS_LE32(ofdm, fina_cnt);
		PRINT_STATS_LE32(ofdm, plcp_err);
		PRINT_STATS_LE32(ofdm, crc32_err);
		PRINT_STATS_LE32(ofdm, overrun_err);
		PRINT_STATS_LE32(ofdm, early_overrun_err);
		PRINT_STATS_LE32(ofdm, crc32_good);
		PRINT_STATS_LE32(ofdm, false_alarm_cnt);
		PRINT_STATS_LE32(ofdm, fina_sync_err_cnt);
		PRINT_STATS_LE32(ofdm, sfd_timeout);
		PRINT_STATS_LE32(ofdm, fina_timeout);
		PRINT_STATS_LE32(ofdm, unresponded_rts);
		PRINT_STATS_LE32(ofdm, rxe_frame_lmt_overrun);
		PRINT_STATS_LE32(ofdm, sent_ack_cnt);
		PRINT_STATS_LE32(ofdm, sent_cts_cnt);
		PRINT_STATS_LE32(ofdm, sent_ba_rsp_cnt);
		PRINT_STATS_LE32(ofdm, dsp_self_kill);
		PRINT_STATS_LE32(ofdm, mh_format_err);
		PRINT_STATS_LE32(ofdm, re_acq_main_rssi_sum);
		PRINT_STATS_LE32(ofdm, reserved);
	} else {
		struct mvm_statistics_rx_phy *ofdm = &mvm->rx_stats.ofdm;

		PRINT_STATS_LE32(ofdm, unresponded_rts);
		PRINT_STATS_LE32(ofdm, rxe_frame_lmt_overrun);
		PRINT_STATS_LE32(ofdm, sent_ba_rsp_cnt);
		PRINT_STATS_LE32(ofdm, dsp_self_kill);
		PRINT_STATS_LE32(ofdm, reserved);
	}

	pos += scnprintf(buf + pos, bufsz - pos, fmt_header,
			 "Statistics_Rx - CCK");
	if (!iwl_mvm_has_new_rx_stats_api(mvm)) {
		struct mvm_statistics_rx_phy_v2 *cck = &mvm->rx_stats_v3.cck;

		PRINT_STATS_LE32(cck, ina_cnt);
		PRINT_STATS_LE32(cck, fina_cnt);
		PRINT_STATS_LE32(cck, plcp_err);
		PRINT_STATS_LE32(cck, crc32_err);
		PRINT_STATS_LE32(cck, overrun_err);
		PRINT_STATS_LE32(cck, early_overrun_err);
		PRINT_STATS_LE32(cck, crc32_good);
		PRINT_STATS_LE32(cck, false_alarm_cnt);
		PRINT_STATS_LE32(cck, fina_sync_err_cnt);
		PRINT_STATS_LE32(cck, sfd_timeout);
		PRINT_STATS_LE32(cck, fina_timeout);
		PRINT_STATS_LE32(cck, unresponded_rts);
		PRINT_STATS_LE32(cck, rxe_frame_lmt_overrun);
		PRINT_STATS_LE32(cck, sent_ack_cnt);
		PRINT_STATS_LE32(cck, sent_cts_cnt);
		PRINT_STATS_LE32(cck, sent_ba_rsp_cnt);
		PRINT_STATS_LE32(cck, dsp_self_kill);
		PRINT_STATS_LE32(cck, mh_format_err);
		PRINT_STATS_LE32(cck, re_acq_main_rssi_sum);
		PRINT_STATS_LE32(cck, reserved);
	} else {
		struct mvm_statistics_rx_phy *cck = &mvm->rx_stats.cck;

		PRINT_STATS_LE32(cck, unresponded_rts);
		PRINT_STATS_LE32(cck, rxe_frame_lmt_overrun);
		PRINT_STATS_LE32(cck, sent_ba_rsp_cnt);
		PRINT_STATS_LE32(cck, dsp_self_kill);
		PRINT_STATS_LE32(cck, reserved);
	}

	pos += scnprintf(buf + pos, bufsz - pos, fmt_header,
			 "Statistics_Rx - GENERAL");
	if (!iwl_mvm_has_new_rx_stats_api(mvm)) {
		struct mvm_statistics_rx_non_phy_v3 *general =
			&mvm->rx_stats_v3.general;

		PRINT_STATS_LE32(general, bogus_cts);
		PRINT_STATS_LE32(general, bogus_ack);
		PRINT_STATS_LE32(general, non_bssid_frames);
		PRINT_STATS_LE32(general, filtered_frames);
		PRINT_STATS_LE32(general, non_channel_beacons);
		PRINT_STATS_LE32(general, channel_beacons);
		PRINT_STATS_LE32(general, num_missed_bcon);
		PRINT_STATS_LE32(general, adc_rx_saturation_time);
		PRINT_STATS_LE32(general, ina_detection_search_time);
		PRINT_STATS_LE32(general, beacon_silence_rssi_a);
		PRINT_STATS_LE32(general, beacon_silence_rssi_b);
		PRINT_STATS_LE32(general, beacon_silence_rssi_c);
		PRINT_STATS_LE32(general, interference_data_flag);
		PRINT_STATS_LE32(general, channel_load);
		PRINT_STATS_LE32(general, dsp_false_alarms);
		PRINT_STATS_LE32(general, beacon_rssi_a);
		PRINT_STATS_LE32(general, beacon_rssi_b);
		PRINT_STATS_LE32(general, beacon_rssi_c);
		PRINT_STATS_LE32(general, beacon_energy_a);
		PRINT_STATS_LE32(general, beacon_energy_b);
		PRINT_STATS_LE32(general, beacon_energy_c);
		PRINT_STATS_LE32(general, num_bt_kills);
		PRINT_STATS_LE32(general, mac_id);
		PRINT_STATS_LE32(general, directed_data_mpdu);
	} else {
		struct mvm_statistics_rx_non_phy *general =
			&mvm->rx_stats.general;

		PRINT_STATS_LE32(general, bogus_cts);
		PRINT_STATS_LE32(general, bogus_ack);
		PRINT_STATS_LE32(general, non_channel_beacons);
		PRINT_STATS_LE32(general, channel_beacons);
		PRINT_STATS_LE32(general, num_missed_bcon);
		PRINT_STATS_LE32(general, adc_rx_saturation_time);
		PRINT_STATS_LE32(general, ina_detection_search_time);
		PRINT_STATS_LE32(general, beacon_silence_rssi_a);
		PRINT_STATS_LE32(general, beacon_silence_rssi_b);
		PRINT_STATS_LE32(general, beacon_silence_rssi_c);
		PRINT_STATS_LE32(general, interference_data_flag);
		PRINT_STATS_LE32(general, channel_load);
		PRINT_STATS_LE32(general, beacon_rssi_a);
		PRINT_STATS_LE32(general, beacon_rssi_b);
		PRINT_STATS_LE32(general, beacon_rssi_c);
		PRINT_STATS_LE32(general, beacon_energy_a);
		PRINT_STATS_LE32(general, beacon_energy_b);
		PRINT_STATS_LE32(general, beacon_energy_c);
		PRINT_STATS_LE32(general, num_bt_kills);
		PRINT_STATS_LE32(general, mac_id);
	}

	pos += scnprintf(buf + pos, bufsz - pos, fmt_header,
			 "Statistics_Rx - HT");
	if (!iwl_mvm_has_new_rx_stats_api(mvm)) {
		struct mvm_statistics_rx_ht_phy_v1 *ht =
			&mvm->rx_stats_v3.ofdm_ht;

		PRINT_STATS_LE32(ht, plcp_err);
		PRINT_STATS_LE32(ht, overrun_err);
		PRINT_STATS_LE32(ht, early_overrun_err);
		PRINT_STATS_LE32(ht, crc32_good);
		PRINT_STATS_LE32(ht, crc32_err);
		PRINT_STATS_LE32(ht, mh_format_err);
		PRINT_STATS_LE32(ht, agg_crc32_good);
		PRINT_STATS_LE32(ht, agg_mpdu_cnt);
		PRINT_STATS_LE32(ht, agg_cnt);
		PRINT_STATS_LE32(ht, unsupport_mcs);
	} else {
		struct mvm_statistics_rx_ht_phy *ht =
			&mvm->rx_stats.ofdm_ht;

		PRINT_STATS_LE32(ht, mh_format_err);
		PRINT_STATS_LE32(ht, agg_mpdu_cnt);
		PRINT_STATS_LE32(ht, agg_cnt);
		PRINT_STATS_LE32(ht, unsupport_mcs);
	}

	mutex_unlock(&mvm->mutex);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, pos);
	kfree(buf);

	return ret;
}
#undef PRINT_STAT_LE32

static ssize_t iwl_dbgfs_frame_stats_read(struct iwl_mvm *mvm,
					  char __user *user_buf, size_t count,
					  loff_t *ppos,
					  struct iwl_mvm_frame_stats *stats)
{
	char *buff, *pos, *endpos;
	int idx, i;
	int ret;
	static const size_t bufsz = 1024;

	buff = kmalloc(bufsz, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	spin_lock_bh(&mvm->drv_stats_lock);

	pos = buff;
	endpos = pos + bufsz;

	pos += scnprintf(pos, endpos - pos,
			 "Legacy/HT/VHT\t:\t%d/%d/%d\n",
			 stats->legacy_frames,
			 stats->ht_frames,
			 stats->vht_frames);
	pos += scnprintf(pos, endpos - pos, "20/40/80\t:\t%d/%d/%d\n",
			 stats->bw_20_frames,
			 stats->bw_40_frames,
			 stats->bw_80_frames);
	pos += scnprintf(pos, endpos - pos, "NGI/SGI\t\t:\t%d/%d\n",
			 stats->ngi_frames,
			 stats->sgi_frames);
	pos += scnprintf(pos, endpos - pos, "SISO/MIMO2\t:\t%d/%d\n",
			 stats->siso_frames,
			 stats->mimo2_frames);
	pos += scnprintf(pos, endpos - pos, "FAIL/SCSS\t:\t%d/%d\n",
			 stats->fail_frames,
			 stats->success_frames);
	pos += scnprintf(pos, endpos - pos, "MPDUs agg\t:\t%d\n",
			 stats->agg_frames);
	pos += scnprintf(pos, endpos - pos, "A-MPDUs\t\t:\t%d\n",
			 stats->ampdu_count);
	pos += scnprintf(pos, endpos - pos, "Avg MPDUs/A-MPDU:\t%d\n",
			 stats->ampdu_count > 0 ?
			 (stats->agg_frames / stats->ampdu_count) : 0);

	pos += scnprintf(pos, endpos - pos, "Last Rates\n");

	idx = stats->last_frame_idx - 1;
	for (i = 0; i < ARRAY_SIZE(stats->last_rates); i++) {
		idx = (idx + 1) % ARRAY_SIZE(stats->last_rates);
		if (stats->last_rates[idx] == 0)
			continue;
		pos += scnprintf(pos, endpos - pos, "Rate[%d]: ",
				 (int)(ARRAY_SIZE(stats->last_rates) - i));
		pos += rs_pretty_print_rate_v1(pos, endpos - pos,
					       stats->last_rates[idx]);
		if (pos < endpos - 1)
			*pos++ = '\n';
	}
	spin_unlock_bh(&mvm->drv_stats_lock);

	ret = simple_read_from_buffer(user_buf, count, ppos, buff, pos - buff);
	kfree(buff);

	return ret;
}

static ssize_t iwl_dbgfs_drv_rx_stats_read(struct file *file,
					   char __user *user_buf, size_t count,
					   loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;

	return iwl_dbgfs_frame_stats_read(mvm, user_buf, count, ppos,
					  &mvm->drv_rx_stats);
}

static ssize_t iwl_dbgfs_fw_restart_write(struct iwl_mvm *mvm, char *buf,
					  size_t count, loff_t *ppos)
{
	int __maybe_unused ret;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	mutex_lock(&mvm->mutex);

	/* allow one more restart that we're provoking here */
	if (mvm->fw_restart >= 0)
		mvm->fw_restart++;

	if (count == 6 && !strcmp(buf, "nolog\n")) {
		set_bit(IWL_MVM_STATUS_SUPPRESS_ERROR_LOG_ONCE, &mvm->status);
		set_bit(STATUS_SUPPRESS_CMD_ERROR_ONCE, &mvm->trans->status);
	}

	/* take the return value to make compiler happy - it will fail anyway */
	ret = iwl_mvm_send_cmd_pdu(mvm,
				   WIDE_ID(LONG_GROUP, REPLY_ERROR),
				   0, 0, NULL);

	mutex_unlock(&mvm->mutex);

	return count;
}

static ssize_t iwl_dbgfs_fw_nmi_write(struct iwl_mvm *mvm, char *buf,
				      size_t count, loff_t *ppos)
{
	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	if (count == 6 && !strcmp(buf, "nolog\n"))
		set_bit(IWL_MVM_STATUS_SUPPRESS_ERROR_LOG_ONCE, &mvm->status);

	iwl_force_nmi(mvm->trans);

	return count;
}

static ssize_t
iwl_dbgfs_scan_ant_rxchain_read(struct file *file,
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	int pos = 0;
	char buf[32];
	const size_t bufsz = sizeof(buf);

	/* print which antennas were set for the scan command by the user */
	pos += scnprintf(buf + pos, bufsz - pos, "Antennas for scan: ");
	if (mvm->scan_rx_ant & ANT_A)
		pos += scnprintf(buf + pos, bufsz - pos, "A");
	if (mvm->scan_rx_ant & ANT_B)
		pos += scnprintf(buf + pos, bufsz - pos, "B");
	pos += scnprintf(buf + pos, bufsz - pos, " (%hhx)\n", mvm->scan_rx_ant);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t
iwl_dbgfs_scan_ant_rxchain_write(struct iwl_mvm *mvm, char *buf,
				 size_t count, loff_t *ppos)
{
	u8 scan_rx_ant;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	if (sscanf(buf, "%hhx", &scan_rx_ant) != 1)
		return -EINVAL;
	if (scan_rx_ant > ANT_ABC)
		return -EINVAL;
	if (scan_rx_ant & ~(iwl_mvm_get_valid_rx_ant(mvm)))
		return -EINVAL;

	if (mvm->scan_rx_ant != scan_rx_ant) {
		mvm->scan_rx_ant = scan_rx_ant;
		if (fw_has_capa(&mvm->fw->ucode_capa,
				IWL_UCODE_TLV_CAPA_UMAC_SCAN))
			iwl_mvm_config_scan(mvm);
	}

	return count;
}

static ssize_t iwl_dbgfs_indirection_tbl_write(struct iwl_mvm *mvm,
					       char *buf, size_t count,
					       loff_t *ppos)
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

	mutex_lock(&mvm->mutex);
	if (iwl_mvm_firmware_running(mvm))
		ret = iwl_mvm_send_cmd_pdu(mvm, RSS_CONFIG_CMD, 0,
					   sizeof(cmd), &cmd);
	else
		ret = 0;
	mutex_unlock(&mvm->mutex);

	return ret ?: count;
}

static ssize_t iwl_dbgfs_inject_packet_write(struct iwl_mvm *mvm,
					     char *buf, size_t count,
					     loff_t *ppos)
{
	struct iwl_op_mode *opmode = container_of((void *)mvm,
						  struct iwl_op_mode,
						  op_mode_specific);
	struct iwl_rx_cmd_buffer rxb = {
		._rx_page_order = 0,
		.truesize = 0, /* not used */
		._offset = 0,
	};
	struct iwl_rx_packet *pkt;
	int bin_len = count / 2;
	int ret = -EINVAL;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	/* supporting only MQ RX */
	if (!mvm->trans->trans_cfg->mq_rx_supported)
		return -ENOTSUPP;

	rxb._page = alloc_pages(GFP_ATOMIC, 0);
	if (!rxb._page)
		return -ENOMEM;
	pkt = rxb_addr(&rxb);

	ret = hex2bin(page_address(rxb._page), buf, bin_len);
	if (ret)
		goto out;

	/* avoid invalid memory access and malformed packet */
	if (bin_len < sizeof(*pkt) ||
	    bin_len != sizeof(*pkt) + iwl_rx_packet_payload_len(pkt))
		goto out;

	local_bh_disable();
	iwl_mvm_rx_mq(opmode, NULL, &rxb);
	local_bh_enable();
	ret = 0;

out:
	iwl_free_rxb(&rxb);

	return ret ?: count;
}

static int _iwl_dbgfs_inject_beacon_ie(struct iwl_mvm *mvm, char *bin, int len)
{
	struct ieee80211_vif *vif;
	struct iwl_mvm_vif *mvmvif;
	struct sk_buff *beacon;
	struct ieee80211_tx_info *info;
	struct iwl_mac_beacon_cmd beacon_cmd = {};
	u8 rate;
	int i;

	len /= 2;

	/* Element len should be represented by u8 */
	if (len >= U8_MAX)
		return -EINVAL;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	if (!iwl_mvm_has_new_tx_api(mvm) &&
	    !fw_has_api(&mvm->fw->ucode_capa,
			IWL_UCODE_TLV_API_NEW_BEACON_TEMPLATE))
		return -EINVAL;

	mutex_lock(&mvm->mutex);

	for (i = 0; i < NUM_MAC_INDEX_DRIVER; i++) {
		vif = iwl_mvm_rcu_dereference_vif_id(mvm, i, false);
		if (!vif)
			continue;

		if (vif->type == NL80211_IFTYPE_AP)
			break;
	}

	if (i == NUM_MAC_INDEX_DRIVER || !vif)
		goto out_err;

	mvm->hw->extra_beacon_tailroom = len;

	beacon = ieee80211_beacon_get_template(mvm->hw, vif, NULL);
	if (!beacon)
		goto out_err;

	if (len && hex2bin(skb_put_zero(beacon, len), bin, len)) {
		dev_kfree_skb(beacon);
		goto out_err;
	}

	mvm->beacon_inject_active = true;

	mvmvif = iwl_mvm_vif_from_mac80211(vif);
	info = IEEE80211_SKB_CB(beacon);
	rate = iwl_mvm_mac_ctxt_get_lowest_rate(info, vif);

	beacon_cmd.flags =
		cpu_to_le16(iwl_mvm_mac_ctxt_get_beacon_flags(mvm->fw, rate));
	beacon_cmd.byte_cnt = cpu_to_le16((u16)beacon->len);
	beacon_cmd.template_id = cpu_to_le32((u32)mvmvif->id);

	iwl_mvm_mac_ctxt_set_tim(mvm, &beacon_cmd.tim_idx,
				 &beacon_cmd.tim_size,
				 beacon->data, beacon->len);

	iwl_mvm_mac_ctxt_send_beacon_cmd(mvm, beacon, &beacon_cmd,
					 sizeof(beacon_cmd));
	mutex_unlock(&mvm->mutex);

	dev_kfree_skb(beacon);

	return 0;

out_err:
	mutex_unlock(&mvm->mutex);
	return -EINVAL;
}

static ssize_t iwl_dbgfs_inject_beacon_ie_write(struct iwl_mvm *mvm,
						char *buf, size_t count,
						loff_t *ppos)
{
	int ret = _iwl_dbgfs_inject_beacon_ie(mvm, buf, count);

	mvm->hw->extra_beacon_tailroom = 0;
	return ret ?: count;
}

static ssize_t iwl_dbgfs_inject_beacon_ie_restore_write(struct iwl_mvm *mvm,
							char *buf,
							size_t count,
							loff_t *ppos)
{
	int ret = _iwl_dbgfs_inject_beacon_ie(mvm, NULL, 0);

	mvm->hw->extra_beacon_tailroom = 0;
	mvm->beacon_inject_active = false;
	return ret ?: count;
}

static ssize_t iwl_dbgfs_fw_dbg_conf_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	int conf;
	char buf[8];
	const size_t bufsz = sizeof(buf);
	int pos = 0;

	mutex_lock(&mvm->mutex);
	conf = mvm->fwrt.dump.conf;
	mutex_unlock(&mvm->mutex);

	pos += scnprintf(buf + pos, bufsz - pos, "%d\n", conf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_fw_dbg_conf_write(struct iwl_mvm *mvm,
					   char *buf, size_t count,
					   loff_t *ppos)
{
	unsigned int conf_id;
	int ret;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	ret = kstrtouint(buf, 0, &conf_id);
	if (ret)
		return ret;

	if (WARN_ON(conf_id >= FW_DBG_CONF_MAX))
		return -EINVAL;

	mutex_lock(&mvm->mutex);
	ret = iwl_fw_start_dbg_conf(&mvm->fwrt, conf_id);
	mutex_unlock(&mvm->mutex);

	return ret ?: count;
}

static ssize_t iwl_dbgfs_fw_dbg_collect_write(struct iwl_mvm *mvm,
					      char *buf, size_t count,
					      loff_t *ppos)
{
	if (count == 0)
		return 0;

	iwl_dbg_tlv_time_point(&mvm->fwrt, IWL_FW_INI_TIME_POINT_USER_TRIGGER,
			       NULL);

	iwl_fw_dbg_collect(&mvm->fwrt, FW_DBG_TRIGGER_USER, buf,
			   (count - 1), NULL);

	return count;
}

static ssize_t iwl_dbgfs_dbg_time_point_write(struct iwl_mvm *mvm,
					      char *buf, size_t count,
					      loff_t *ppos)
{
	u32 timepoint;

	if (kstrtou32(buf, 0, &timepoint))
		return -EINVAL;

	if (timepoint == IWL_FW_INI_TIME_POINT_INVALID ||
	    timepoint >= IWL_FW_INI_TIME_POINT_NUM)
		return -EINVAL;

	iwl_dbg_tlv_time_point(&mvm->fwrt, timepoint, NULL);

	return count;
}

#define MVM_DEBUGFS_WRITE_FILE_OPS(name, bufsz) \
	_MVM_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct iwl_mvm)
#define MVM_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz) \
	_MVM_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz, struct iwl_mvm)
#define MVM_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
		debugfs_create_file(alias, mode, parent, mvm,		\
				    &iwl_dbgfs_##name##_ops);		\
	} while (0)
#define MVM_DEBUGFS_ADD_FILE(name, parent, mode) \
	MVM_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

#define MVM_DEBUGFS_WRITE_STA_FILE_OPS(name, bufsz) \
	_MVM_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct ieee80211_sta)
#define MVM_DEBUGFS_READ_WRITE_STA_FILE_OPS(name, bufsz) \
	_MVM_DEBUGFS_READ_WRITE_FILE_OPS(name, bufsz, struct ieee80211_sta)

#define MVM_DEBUGFS_ADD_STA_FILE_ALIAS(alias, name, parent, mode) do {	\
		debugfs_create_file(alias, mode, parent, sta,		\
				    &iwl_dbgfs_##name##_ops);		\
	} while (0)
#define MVM_DEBUGFS_ADD_STA_FILE(name, parent, mode) \
	MVM_DEBUGFS_ADD_STA_FILE_ALIAS(#name, name, parent, mode)

static ssize_t
iwl_dbgfs_prph_reg_read(struct file *file,
			char __user *user_buf,
			size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	int pos = 0;
	char buf[32];
	const size_t bufsz = sizeof(buf);

	if (!mvm->dbgfs_prph_reg_addr)
		return -EINVAL;

	pos += scnprintf(buf + pos, bufsz - pos, "Reg 0x%x: (0x%x)\n",
		mvm->dbgfs_prph_reg_addr,
		iwl_read_prph(mvm->trans, mvm->dbgfs_prph_reg_addr));

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t
iwl_dbgfs_prph_reg_write(struct iwl_mvm *mvm, char *buf,
			 size_t count, loff_t *ppos)
{
	u8 args;
	u32 value;

	args = sscanf(buf, "%i %i", &mvm->dbgfs_prph_reg_addr, &value);
	/* if we only want to set the reg address - nothing more to do */
	if (args == 1)
		goto out;

	/* otherwise, make sure we have both address and value */
	if (args != 2)
		return -EINVAL;

	iwl_write_prph(mvm->trans, mvm->dbgfs_prph_reg_addr, value);

out:
	return count;
}

static ssize_t
iwl_dbgfs_send_echo_cmd_write(struct iwl_mvm *mvm, char *buf,
			      size_t count, loff_t *ppos)
{
	int ret;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd_pdu(mvm, ECHO_CMD, 0, 0, NULL);
	mutex_unlock(&mvm->mutex);

	return ret ?: count;
}

struct iwl_mvm_sniffer_apply {
	struct iwl_mvm *mvm;
	u8 *bssid;
	u16 aid;
};

static bool iwl_mvm_sniffer_apply(struct iwl_notif_wait_data *notif_data,
				  struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_mvm_sniffer_apply *apply = data;

	apply->mvm->cur_aid = cpu_to_le16(apply->aid);
	memcpy(apply->mvm->cur_bssid, apply->bssid,
	       sizeof(apply->mvm->cur_bssid));

	return true;
}

static ssize_t
iwl_dbgfs_he_sniffer_params_write(struct iwl_mvm *mvm, char *buf,
				  size_t count, loff_t *ppos)
{
	struct iwl_notification_wait wait;
	struct iwl_he_monitor_cmd he_mon_cmd = {};
	struct iwl_mvm_sniffer_apply apply = {
		.mvm = mvm,
	};
	u16 wait_cmds[] = {
		WIDE_ID(DATA_PATH_GROUP, HE_AIR_SNIFFER_CONFIG_CMD),
	};
	u32 aid;
	int ret;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	ret = sscanf(buf, "%x %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &aid,
		     &he_mon_cmd.bssid[0], &he_mon_cmd.bssid[1],
		     &he_mon_cmd.bssid[2], &he_mon_cmd.bssid[3],
		     &he_mon_cmd.bssid[4], &he_mon_cmd.bssid[5]);
	if (ret != 7)
		return -EINVAL;

	he_mon_cmd.aid = cpu_to_le16(aid);

	apply.aid = aid;
	apply.bssid = (void *)he_mon_cmd.bssid;

	mutex_lock(&mvm->mutex);

	/*
	 * Use the notification waiter to get our function triggered
	 * in sequence with other RX. This ensures that frames we get
	 * on the RX queue _before_ the new configuration is applied
	 * still have mvm->cur_aid pointing to the old AID, and that
	 * frames on the RX queue _after_ the firmware processed the
	 * new configuration (and sent the response, synchronously)
	 * get mvm->cur_aid correctly set to the new AID.
	 */
	iwl_init_notification_wait(&mvm->notif_wait, &wait,
				   wait_cmds, ARRAY_SIZE(wait_cmds),
				   iwl_mvm_sniffer_apply, &apply);

	ret = iwl_mvm_send_cmd_pdu(mvm,
				   WIDE_ID(DATA_PATH_GROUP, HE_AIR_SNIFFER_CONFIG_CMD),
				   0,
				   sizeof(he_mon_cmd), &he_mon_cmd);

	/* no need to really wait, we already did anyway */
	iwl_remove_notification(&mvm->notif_wait, &wait);

	mutex_unlock(&mvm->mutex);

	return ret ?: count;
}

static ssize_t
iwl_dbgfs_he_sniffer_params_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	u8 buf[32];
	int len;

	len = scnprintf(buf, sizeof(buf),
			"%d %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
			le16_to_cpu(mvm->cur_aid), mvm->cur_bssid[0],
			mvm->cur_bssid[1], mvm->cur_bssid[2], mvm->cur_bssid[3],
			mvm->cur_bssid[4], mvm->cur_bssid[5]);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t
iwl_dbgfs_uapsd_noagg_bssids_read(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	u8 buf[IWL_MVM_UAPSD_NOAGG_BSSIDS_NUM * ETH_ALEN * 3 + 1];
	unsigned int pos = 0;
	size_t bufsz = sizeof(buf);
	int i;

	mutex_lock(&mvm->mutex);

	for (i = 0; i < IWL_MVM_UAPSD_NOAGG_LIST_LEN; i++)
		pos += scnprintf(buf + pos, bufsz - pos, "%pM\n",
				 mvm->uapsd_noagg_bssids[i].addr);

	mutex_unlock(&mvm->mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

#ifdef CPTCFG_IWLMVM_VENDOR_CMDS
static ssize_t iwl_dbgfs_tx_power_status_read(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	char buf[64];
	int bufsz = sizeof(buf);
	int pos = 0;
	u32 mode = le32_to_cpu(mvm->txp_cmd.common.set_mode);
	bool txp_cmd_valid = mode == IWL_TX_POWER_MODE_SET_DEVICE;
	u16 val_24 = le16_to_cpu(mvm->txp_cmd.common.dev_24);
	u16 val_52l = le16_to_cpu(mvm->txp_cmd.common.dev_52_low);
	u16 val_52h = le16_to_cpu(mvm->txp_cmd.common.dev_52_high);
	char buf_24[15] = "(not limited)";
	char buf_52l[15] = "(not limited)";
	char buf_52h[15] = "(not limited)";

	if (txp_cmd_valid && val_24 < IWL_DEV_MAX_TX_POWER)
		sprintf(buf_24, "%d.%03d dBm", val_24 >> 3, (val_24 & 7) * 125);
	if (txp_cmd_valid && val_52l < IWL_DEV_MAX_TX_POWER)
		sprintf(buf_52l, "%d.%03d dBm",
			val_52l >> 3, (val_52l & 7) * 125);
	if (txp_cmd_valid && val_52h < IWL_DEV_MAX_TX_POWER)
		sprintf(buf_52h, "%d.%03d dBm",
			val_52h >> 3, (val_52h & 7) * 125);

	pos += scnprintf(buf + pos, bufsz - pos, "2.4 = %s\n", buf_24);
	pos += scnprintf(buf + pos, bufsz - pos, "5.2L = %s\n", buf_52l);
	pos += scnprintf(buf + pos, bufsz - pos, "5.2H = %s\n", buf_52h);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

static ssize_t iwl_dbgfs_csi_enabled_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	u8 buf[] = {
		mvm->csi_cfg.flags & IWL_CHANNEL_ESTIMATION_ENABLE ? '1' : '0',
		'\n'
	};

	return simple_read_from_buffer(user_buf, count, ppos, buf, 2);
}

static ssize_t iwl_dbgfs_csi_enabled_write(struct iwl_mvm *mvm, char *buf,
					   size_t count, loff_t *ppos)
{
	int err;
	bool enabled;

	if (buf[count - 1] != '\n')
		return -EINVAL;
	buf[count - 1] = 0;

	err = kstrtobool(buf, &enabled);
	if (err)
		return err;

	/*
	 * disable -> disable is a no-op, but
	 * enable -> enable resets the timer/count
	 */
	if (!enabled && !(mvm->csi_cfg.flags & IWL_CHANNEL_ESTIMATION_ENABLE))
		return count;

	mutex_lock(&mvm->mutex);
	mvm->csi_cfg.flags &= ~IWL_CHANNEL_ESTIMATION_ENABLE;
	if (enabled)
		mvm->csi_cfg.flags |= IWL_CHANNEL_ESTIMATION_ENABLE;

	if (iwl_mvm_firmware_running(mvm))
		err = iwl_mvm_send_csi_cmd(mvm);
	mutex_unlock(&mvm->mutex);

	return err ?: count;
}

static ssize_t iwl_dbgfs_csi_count_read(struct file *file,
					char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	s64 ctr = -1;
	u8 buf[32];
	int len;

	if (mvm->csi_cfg.flags & IWL_CHANNEL_ESTIMATION_COUNTER)
		ctr = mvm->csi_cfg.count;
	len = scnprintf(buf, sizeof(buf), "%lld\n", ctr);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t iwl_dbgfs_csi_count_write(struct iwl_mvm *mvm, char *buf,
					 size_t count, loff_t *ppos)
{
	int err;
	s64 ctr;

	if (buf[count - 1] != '\n')
		return -EINVAL;
	buf[count - 1] = 0;

	err = kstrtos64(buf, 0, &ctr);
	if (err)
		return err;

	if (ctr <= 0) {
		mvm->csi_cfg.flags &= ~IWL_CHANNEL_ESTIMATION_COUNTER;
		mvm->csi_cfg.count = 0;
	} else if (ctr <= UINT_MAX) {
		mvm->csi_cfg.flags |= IWL_CHANNEL_ESTIMATION_COUNTER;
		mvm->csi_cfg.count = ctr;
	} else {
		return -ERANGE;
	}

	return count;
}

static ssize_t iwl_dbgfs_csi_timeout_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	s64 timer = -1;
	u8 buf[32];
	int len;

	if (mvm->csi_cfg.flags & IWL_CHANNEL_ESTIMATION_TIMER)
		timer = mvm->csi_cfg.timer;
	len = scnprintf(buf, sizeof(buf), "%lld\n", timer);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t iwl_dbgfs_csi_timeout_write(struct iwl_mvm *mvm, char *buf,
					   size_t count, loff_t *ppos)
{
	int err;
	s64 timer;

	if (buf[count - 1] != '\n')
		return -EINVAL;
	buf[count - 1] = 0;

	err = kstrtos64(buf, 0, &timer);
	if (err)
		return err;

	if (timer < 0) {
		mvm->csi_cfg.flags &= ~IWL_CHANNEL_ESTIMATION_TIMER;
		mvm->csi_cfg.timer = 0;
	} else if (timer <= UINT_MAX) {
		mvm->csi_cfg.flags |= IWL_CHANNEL_ESTIMATION_TIMER;
		mvm->csi_cfg.timer = timer;
	} else {
		return -ERANGE;
	}

	return count;
}

static ssize_t iwl_dbgfs_csi_frame_types_read(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	u8 buf[32];
	int len;

	len = scnprintf(buf, sizeof(buf), "0x%llx\n", mvm->csi_cfg.frame_types);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t iwl_dbgfs_csi_frame_types_write(struct iwl_mvm *mvm, char *buf,
					       size_t count, loff_t *ppos)
{
	int err;
	u64 frame_types;

	if (buf[count - 1] != '\n')
		return -EINVAL;
	buf[count - 1] = 0;

	err = kstrtou64(buf, 0, &frame_types);
	if (err)
		return err;

	mvm->csi_cfg.frame_types = frame_types;

	return count;
}

static ssize_t iwl_dbgfs_csi_interval_read(struct file *file,
					   char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	u8 buf[32];
	int len;

	len = scnprintf(buf, sizeof(buf), "%u\n", mvm->csi_cfg.interval);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t iwl_dbgfs_csi_interval_write(struct iwl_mvm *mvm, char *buf,
					    size_t count, loff_t *ppos)
{
	int err;
	u32 interval;

	if (buf[count - 1] != '\n')
		return -EINVAL;
	buf[count - 1] = 0;

	err = kstrtou32(buf, 0, &interval);
	if (err)
		return err;

	mvm->csi_cfg.interval = interval;
	if (interval)
		mvm->csi_cfg.flags |= IWL_CHANNEL_ESTIMATION_INTERVAL;
	else
		mvm->csi_cfg.flags &= ~IWL_CHANNEL_ESTIMATION_INTERVAL;

	return count;
}

static ssize_t iwl_dbgfs_csi_addresses_read(struct file *file,
					    char __user *user_buf,
					    size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	u8 buf[2 + ETH_ALEN * 3 * IWL_NUM_CHANNEL_ESTIMATION_FILTER_ADDRS];
	u8 *pos = buf;
	int i;

	for (i = 0; i < mvm->csi_cfg.num_filter_addrs; i++)
		pos += scnprintf(pos, sizeof(buf) - (pos - buf),
				 "%pM\n", mvm->csi_cfg.filter_addrs[i].addr);

	return simple_read_from_buffer(user_buf, count, ppos, buf, pos - buf);
}

static ssize_t iwl_dbgfs_csi_addresses_write(struct iwl_mvm *mvm, char *buf,
					     size_t count, loff_t *ppos)
{
	char *pos = buf;
	int num = 0, i;
	struct {
		u8 addr[ETH_ALEN] __aligned(2);
	} addrs[IWL_NUM_CHANNEL_ESTIMATION_FILTER_ADDRS];

	if (buf[count - 1] != '\n')
		return -EINVAL;
	buf[count - 1] = 0;

	while (num < IWL_NUM_CHANNEL_ESTIMATION_FILTER_ADDRS) {
		char *addrstr = strsep(&pos, "\n ");
		u8 addr[ETH_ALEN];
		int n;

		if (!addrstr || !*addrstr)
			break;

		n = sscanf(addrstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			   &addr[0], &addr[1], &addr[2],
			   &addr[3], &addr[4], &addr[5]);

		if (n != ETH_ALEN)
			return -EINVAL;

		ether_addr_copy(addrs[num].addr, addr);
		num++;
	}

	/* too many specified if the string isn't NULL now */
	if (pos)
		return -EINVAL;

	mvm->csi_cfg.num_filter_addrs = num;
	for (i = 0; i < num; i++)
		ether_addr_copy(mvm->csi_cfg.filter_addrs[i].addr,
				addrs[i].addr);

	return count;
}
#endif /* CPTCFG_IWLMVM_VENDOR_CMDS */

#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
static ssize_t iwl_dbgfs_debug_profile_write(struct iwl_mvm *mvm, char *buf,
					     size_t count, loff_t *ppos)
{
	struct iwl_dhc_cmd *dhc_cmd;
	struct iwl_dhc_profile_cmd *profile_cmd;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(IWL_ALWAYS_LONG_GROUP, DEBUG_HOST_COMMAND),
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
	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd(mvm, &hcmd);
	if (ret)
		IWL_ERR(mvm, "failed to send DHC profiling cmd\n");
	mutex_unlock(&mvm->mutex);
	kfree(dhc_cmd);

	return ret ?: count;
}

static ssize_t iwl_dbgfs_send_dhc(struct iwl_mvm *mvm, char *buf,
				  u32 index_and_mask)
{
	int ret;
	u32 user_val;
	__le32 cmd_data;

	struct iwl_dhc_cmd cmd = {
		.length = cpu_to_le32(1),
		.index_and_mask = cpu_to_le32(index_and_mask),
	};

	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(LEGACY_GROUP, DEBUG_HOST_COMMAND),
		.data = { &cmd, &cmd_data},
		.len = { sizeof(cmd), sizeof(cmd_data) },
	};

	IWL_DEBUG_INFO(mvm, "Sending DHC index_and_mask 0x%x\n",
		       index_and_mask);

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	ret = kstrtou32(buf, 10, &user_val);
	cmd_data = cpu_to_le32(user_val);

	if (ret < 0)
		return ret;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd(mvm, &hcmd);
	mutex_unlock(&mvm->mutex);

	return ret;
}

static ssize_t
iwl_dbgfs_enable_adwell_fine_tune_report_write(struct iwl_mvm *mvm, char *buf,
					       size_t count, loff_t *ppos)
{
	int ret;
	u32 index_and_mask =
		DHC_AUTO_UMAC_ADAPTIVE_DWELL_SCAN_FINE_TUNE_ENABLE_REPORT |
		DHC_TABLE_AUTOMATION | DHC_TARGET_UMAC;

	ret = iwl_dbgfs_send_dhc(mvm, buf, index_and_mask);

	return ret ?: count;
}

static ssize_t
iwl_dbgfs_enable_adwell_channel_dwell_report_write(struct iwl_mvm *mvm,
						   char *buf,
						   size_t count, loff_t *ppos)
{
	int ret;
	u32 index_and_mask =
		DHC_AUTO_UMAC_SCAN_CHANNEL_DWELL_ENABLE_REPORT |
		DHC_TABLE_AUTOMATION | DHC_TARGET_UMAC;

	ret = iwl_dbgfs_send_dhc(mvm, buf, index_and_mask);

	return ret ?: count;
}

static ssize_t iwl_dbgfs_disable_tx_fifo_mask_write(struct iwl_mvm *mvm,
						    char *buf,
						    size_t count,
						    loff_t *ppos)
{
	int ret;

	u32 index_and_mask = DHC_TOOLS_LMAC_TXF_FIFO_DISABLE;

	set_bit(STATUS_DISABLE_STUCK_TIMER, &mvm->trans->status);

	ret = iwl_dbgfs_send_dhc(mvm, buf, index_and_mask);

	return ret ?: count;
}

static ssize_t iwl_dbgfs_ps_config_write(struct iwl_mvm *mvm,
					 char *buf,
					 size_t count,
					 loff_t *ppos)
{
	int ret;
	struct iwl_ps_config cmd_data;

	if (sscanf(buf, "%x %x %x",
		   &cmd_data.pwr_flags,
		   &cmd_data.pwr_flags_msk,
		   &cmd_data.param1) != 3)
		return -EINVAL;

	ret = iwl_dbgfs_send_ps_config_dhc(mvm, &cmd_data);

	return ret ?: count;
}

#endif /* CPTCFG_IWLWIFI_DHC_PRIVATE */

static ssize_t
iwl_dbgfs_ltr_config_write(struct iwl_mvm *mvm,
			   char *buf, size_t count, loff_t *ppos)
{
	int ret;
	struct iwl_ltr_config_cmd ltr_config = {0};

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	if (sscanf(buf, "%x,%x,%x,%x,%x,%x,%x",
		   &ltr_config.flags,
		   &ltr_config.static_long,
		   &ltr_config.static_short,
		   &ltr_config.ltr_cfg_values[0],
		   &ltr_config.ltr_cfg_values[1],
		   &ltr_config.ltr_cfg_values[2],
		   &ltr_config.ltr_cfg_values[3]) != 7) {
		return -EINVAL;
	}

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd_pdu(mvm, LTR_CONFIG, 0, sizeof(ltr_config),
				   &ltr_config);
	mutex_unlock(&mvm->mutex);

	if (ret)
		IWL_ERR(mvm, "failed to send ltr configuration cmd\n");

	return ret ?: count;
}

static ssize_t iwl_dbgfs_rfi_freq_table_write(struct iwl_mvm *mvm, char *buf,
					      size_t count, loff_t *ppos)
{
	int ret = 0;
	u16 op_id;

	if (kstrtou16(buf, 10, &op_id))
		return -EINVAL;

	/* value zero triggers re-sending the default table to the device */
	if (!op_id) {
		mutex_lock(&mvm->mutex);
		ret = iwl_rfi_send_config_cmd(mvm, NULL);
		mutex_unlock(&mvm->mutex);
	} else {
		ret = -EOPNOTSUPP; /* in the future a new table will be added */
	}

	return ret ?: count;
}

/* The size computation is as follows:
 * each number needs at most 3 characters, number of rows is the size of
 * the table; So, need 5 chars for the "freq: " part and each tuple afterwards
 * needs 6 characters for numbers and 5 for the punctuation around.
 */
#define IWL_RFI_BUF_SIZE (IWL_RFI_LUT_INSTALLED_SIZE *\
				(5 + IWL_RFI_LUT_ENTRY_CHANNELS_NUM * (6 + 5)))

static ssize_t iwl_dbgfs_rfi_freq_table_read(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct iwl_rfi_freq_table_resp_cmd *resp;
	u32 status;
	char buf[IWL_RFI_BUF_SIZE];
	int i, j, pos = 0;

	resp = iwl_rfi_get_freq_table(mvm);
	if (IS_ERR(resp))
		return PTR_ERR(resp);

	status = le32_to_cpu(resp->status);
	if (status != RFI_FREQ_TABLE_OK) {
		scnprintf(buf, IWL_RFI_BUF_SIZE, "status = %d\n", status);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(resp->table); i++) {
		pos += scnprintf(buf + pos, IWL_RFI_BUF_SIZE - pos, "%d: ",
				 resp->table[i].freq);

		for (j = 0; j < ARRAY_SIZE(resp->table[i].channels); j++)
			pos += scnprintf(buf + pos, IWL_RFI_BUF_SIZE - pos,
					 "(%d, %d) ",
					 resp->table[i].channels[j],
					 resp->table[i].bands[j]);
		pos += scnprintf(buf + pos, IWL_RFI_BUF_SIZE - pos, "\n");
	}

out:
	kfree(resp);
	return simple_read_from_buffer(user_buf, count, ppos, buf, pos);
}

MVM_DEBUGFS_READ_WRITE_FILE_OPS(prph_reg, 64);

/* Device wide debugfs entries */
#ifdef CPTCFG_IWLMVM_ADVANCED_QUOTA_MGMT
MVM_DEBUGFS_READ_FILE_OPS(quota_status);
#endif
#ifdef CPTCFG_IWLWIFI_THERMAL_DEBUGFS
MVM_DEBUGFS_READ_WRITE_FILE_OPS(tt_tx_backoff, 64);
#endif
MVM_DEBUGFS_READ_FILE_OPS(ctdp_budget);
MVM_DEBUGFS_WRITE_FILE_OPS(stop_ctdp, 8);
MVM_DEBUGFS_WRITE_FILE_OPS(force_ctkill, 8);
MVM_DEBUGFS_WRITE_FILE_OPS(tx_flush, 16);
MVM_DEBUGFS_WRITE_FILE_OPS(sta_drain, 8);
MVM_DEBUGFS_WRITE_FILE_OPS(send_echo_cmd, 8);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(sram, 64);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(set_nic_temperature, 64);
MVM_DEBUGFS_READ_FILE_OPS(nic_temp);
MVM_DEBUGFS_READ_FILE_OPS(stations);
MVM_DEBUGFS_READ_FILE_OPS(rs_data);
MVM_DEBUGFS_READ_FILE_OPS(bt_notif);
MVM_DEBUGFS_READ_FILE_OPS(bt_cmd);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(disable_power_off, 64);
MVM_DEBUGFS_READ_FILE_OPS(fw_rx_stats);
MVM_DEBUGFS_READ_FILE_OPS(drv_rx_stats);
MVM_DEBUGFS_READ_FILE_OPS(fw_ver);
MVM_DEBUGFS_READ_FILE_OPS(phy_integration_ver);
MVM_DEBUGFS_WRITE_FILE_OPS(fw_restart, 10);
MVM_DEBUGFS_WRITE_FILE_OPS(fw_nmi, 10);
MVM_DEBUGFS_WRITE_FILE_OPS(bt_tx_prio, 10);
MVM_DEBUGFS_WRITE_FILE_OPS(bt_force_ant, 10);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(scan_ant_rxchain, 8);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(fw_dbg_conf, 8);
MVM_DEBUGFS_WRITE_FILE_OPS(fw_dbg_collect, 64);
MVM_DEBUGFS_WRITE_FILE_OPS(dbg_time_point, 64);
MVM_DEBUGFS_WRITE_FILE_OPS(indirection_tbl,
			   (IWL_RSS_INDIRECTION_TABLE_SIZE * 2));
MVM_DEBUGFS_WRITE_FILE_OPS(inject_packet, 512);
MVM_DEBUGFS_WRITE_FILE_OPS(inject_beacon_ie, 512);
MVM_DEBUGFS_WRITE_FILE_OPS(inject_beacon_ie_restore, 512);
#ifdef CPTCFG_IWLMVM_VENDOR_CMDS
MVM_DEBUGFS_READ_FILE_OPS(tx_power_status);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(csi_enabled, 8);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(csi_count, 32);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(csi_timeout, 32);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(csi_frame_types, 32);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(csi_interval, 32);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(csi_addresses,
				2 + ETH_ALEN * 3 *
				    IWL_NUM_CHANNEL_ESTIMATION_FILTER_ADDRS);
#endif

MVM_DEBUGFS_READ_FILE_OPS(uapsd_noagg_bssids);

#ifdef CONFIG_ACPI
MVM_DEBUGFS_READ_FILE_OPS(sar_geo_profile);
#endif

MVM_DEBUGFS_WRITE_STA_FILE_OPS(fixed_rate, 64);
MVM_DEBUGFS_WRITE_STA_FILE_OPS(ampdu_size, 64);
MVM_DEBUGFS_WRITE_STA_FILE_OPS(disable_rts, 8);
MVM_DEBUGFS_WRITE_STA_FILE_OPS(tlc_dhc, 64);
MVM_DEBUGFS_WRITE_FILE_OPS(iwl_tlc_dhc, 64);
#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
MVM_DEBUGFS_WRITE_FILE_OPS(debug_profile, 64);
MVM_DEBUGFS_WRITE_FILE_OPS(enable_adwell_fine_tune_report, 32);
MVM_DEBUGFS_WRITE_FILE_OPS(enable_adwell_channel_dwell_report, 32);
MVM_DEBUGFS_WRITE_FILE_OPS(disable_tx_fifo_mask, 16);
MVM_DEBUGFS_WRITE_FILE_OPS(ps_config, 32);
#endif /* CPTCFG_IWLWIFI_DHC_PRIVATE */
MVM_DEBUGFS_READ_WRITE_STA_FILE_OPS(amsdu_len, 16);

#ifdef CPTCFG_IWLMVM_AX_SOFTAP_TESTMODE
MVM_DEBUGFS_WRITE_FILE_OPS(ax_softap_client_testmode, 8);
#endif /* CPTCFG_IWLMVM_AX_SOFTAP_TESTMODE */

MVM_DEBUGFS_READ_WRITE_FILE_OPS(he_sniffer_params, 32);

MVM_DEBUGFS_WRITE_FILE_OPS(ltr_config, 512);
MVM_DEBUGFS_READ_WRITE_FILE_OPS(rfi_freq_table, 16);

static ssize_t iwl_dbgfs_mem_read(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct iwl_dbg_mem_access_cmd cmd = {};
	struct iwl_dbg_mem_access_rsp *rsp;
	struct iwl_host_cmd hcmd = {
		.flags = CMD_WANT_SKB | CMD_SEND_IN_RFKILL,
		.data = { &cmd, },
		.len = { sizeof(cmd) },
	};
	size_t delta;
	ssize_t ret, len;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	hcmd.id = WIDE_ID(DEBUG_GROUP, *ppos >> 24 ? UMAC_RD_WR : LMAC_RD_WR);
	cmd.op = cpu_to_le32(DEBUG_MEM_OP_READ);

	/* Take care of alignment of both the position and the length */
	delta = *ppos & 0x3;
	cmd.addr = cpu_to_le32(*ppos - delta);
	cmd.len = cpu_to_le32(min(ALIGN(count + delta, 4) / 4,
				  (size_t)DEBUG_MEM_MAX_SIZE_DWORDS));

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd(mvm, &hcmd);
	mutex_unlock(&mvm->mutex);

	if (ret < 0)
		return ret;

	rsp = (void *)hcmd.resp_pkt->data;
	if (le32_to_cpu(rsp->status) != DEBUG_MEM_STATUS_SUCCESS) {
		ret = -ENXIO;
		goto out;
	}

	len = min((size_t)le32_to_cpu(rsp->len) << 2,
		  iwl_rx_packet_payload_len(hcmd.resp_pkt) - sizeof(*rsp));
	len = min(len - delta, count);
	if (len < 0) {
		ret = -EFAULT;
		goto out;
	}

	ret = len - copy_to_user(user_buf, (u8 *)rsp->data + delta, len);
	*ppos += ret;

out:
	iwl_free_resp(&hcmd);
	return ret;
}

static ssize_t iwl_dbgfs_mem_write(struct file *file,
				   const char __user *user_buf, size_t count,
				   loff_t *ppos)
{
	struct iwl_mvm *mvm = file->private_data;
	struct iwl_dbg_mem_access_cmd *cmd;
	struct iwl_dbg_mem_access_rsp *rsp;
	struct iwl_host_cmd hcmd = {};
	size_t cmd_size;
	size_t data_size;
	u32 op, len;
	ssize_t ret;

	if (!iwl_mvm_firmware_running(mvm))
		return -EIO;

	hcmd.id = WIDE_ID(DEBUG_GROUP, *ppos >> 24 ? UMAC_RD_WR : LMAC_RD_WR);

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

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd(mvm, &hcmd);
	mutex_unlock(&mvm->mutex);

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

void iwl_mvm_sta_add_debugfs(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif,
			     struct ieee80211_sta *sta,
			     struct dentry *dir)
{
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);

#ifdef CPTCFG_IWLMVM_AX_SOFTAP_TESTMODE
	iwl_mvm_ax_softap_testmode_sta_add_debugfs(hw, vif, sta, dir);
#endif

	if (iwl_mvm_has_tlc_offload(mvm)) {
		MVM_DEBUGFS_ADD_STA_FILE(rs_data, dir, 0400);
		MVM_DEBUGFS_ADD_STA_FILE(fixed_rate, dir, 0200);
		MVM_DEBUGFS_ADD_STA_FILE(ampdu_size, dir, 0400);
		MVM_DEBUGFS_ADD_STA_FILE(disable_rts, dir, 0400);
		MVM_DEBUGFS_ADD_STA_FILE(tlc_dhc, dir, 0200);
	}
	MVM_DEBUGFS_ADD_STA_FILE(amsdu_len, dir, 0600);
}

void iwl_mvm_dbgfs_register(struct iwl_mvm *mvm)
{
#ifdef CPTCFG_IWLWIFI_THERMAL_DEBUGFS
	struct iwl_tt_params *tt_params = &mvm->thermal_throttle.params;
#endif
	struct dentry *bcast_dir __maybe_unused;

	spin_lock_init(&mvm->drv_stats_lock);

#ifdef CPTCFG_IWLWIFI_THERMAL_DEBUGFS
	MVM_DEBUGFS_ADD_FILE(tt_tx_backoff, mvm->debugfs_dir, 0400);
#endif
	MVM_DEBUGFS_ADD_FILE(tx_flush, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(sta_drain, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(sram, mvm->debugfs_dir, 0600);
	MVM_DEBUGFS_ADD_FILE(set_nic_temperature, mvm->debugfs_dir, 0600);
	MVM_DEBUGFS_ADD_FILE(nic_temp, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(ctdp_budget, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(stop_ctdp, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(force_ctkill, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(stations, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(bt_notif, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(bt_cmd, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(disable_power_off, mvm->debugfs_dir, 0600);
	MVM_DEBUGFS_ADD_FILE(fw_ver, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(fw_rx_stats, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(drv_rx_stats, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(fw_restart, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(fw_nmi, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(bt_tx_prio, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(bt_force_ant, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(scan_ant_rxchain, mvm->debugfs_dir, 0600);
	MVM_DEBUGFS_ADD_FILE(prph_reg, mvm->debugfs_dir, 0600);
	MVM_DEBUGFS_ADD_FILE(fw_dbg_conf, mvm->debugfs_dir, 0600);
	MVM_DEBUGFS_ADD_FILE(fw_dbg_collect, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(dbg_time_point, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(send_echo_cmd, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(indirection_tbl, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(inject_packet, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(inject_beacon_ie, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(inject_beacon_ie_restore, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(rfi_freq_table, mvm->debugfs_dir, 0600);

	if (mvm->fw->phy_integration_ver)
		MVM_DEBUGFS_ADD_FILE(phy_integration_ver, mvm->debugfs_dir, 0400);
	MVM_DEBUGFS_ADD_FILE(iwl_tlc_dhc, mvm->debugfs_dir, 0400);
#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
	MVM_DEBUGFS_ADD_FILE(debug_profile, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(enable_adwell_fine_tune_report,
			     mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(enable_adwell_channel_dwell_report,
			     mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(disable_tx_fifo_mask, mvm->debugfs_dir, 0200);
	MVM_DEBUGFS_ADD_FILE(ps_config, mvm->debugfs_dir, 0200);
#endif
#ifdef CONFIG_ACPI
	MVM_DEBUGFS_ADD_FILE(sar_geo_profile, mvm->debugfs_dir, 0400);
#endif
#ifdef CPTCFG_IWLMVM_VENDOR_CMDS
	MVM_DEBUGFS_ADD_FILE(tx_power_status, mvm->debugfs_dir, 0400);

	if (fw_has_capa(&mvm->fw->ucode_capa,
			IWL_UCODE_TLV_CAPA_CSI_REPORTING) ||
	    fw_has_capa(&mvm->fw->ucode_capa,
			IWL_UCODE_TLV_CAPA_CSI_REPORTING_V2)) {
		MVM_DEBUGFS_ADD_FILE(csi_enabled, mvm->debugfs_dir, 0600);
		MVM_DEBUGFS_ADD_FILE(csi_count, mvm->debugfs_dir, 0600);
		MVM_DEBUGFS_ADD_FILE(csi_timeout, mvm->debugfs_dir, 0600);
		MVM_DEBUGFS_ADD_FILE(csi_frame_types, mvm->debugfs_dir, 0600);
		debugfs_create_u32("csi_rate_n_flags_val", 0600,
				   mvm->debugfs_dir,
				   &mvm->csi_cfg.rate_n_flags_val);
		debugfs_create_u32("csi_rate_n_flags_mask", 0600,
				   mvm->debugfs_dir,
				   &mvm->csi_cfg.rate_n_flags_mask);
	}

	if (fw_has_capa(&mvm->fw->ucode_capa,
			IWL_UCODE_TLV_CAPA_CSI_REPORTING_V2)) {
		MVM_DEBUGFS_ADD_FILE(csi_interval, mvm->debugfs_dir, 0600);
		MVM_DEBUGFS_ADD_FILE(csi_addresses, mvm->debugfs_dir, 0600);
	}
#endif
#ifdef CPTCFG_IWLMVM_AX_SOFTAP_TESTMODE
	MVM_DEBUGFS_ADD_FILE(ax_softap_client_testmode,
			     mvm->debugfs_dir, 0200);
#endif
	MVM_DEBUGFS_ADD_FILE(he_sniffer_params, mvm->debugfs_dir, 0600);

	if (fw_has_capa(&mvm->fw->ucode_capa, IWL_UCODE_TLV_CAPA_SET_LTR_GEN2))
		MVM_DEBUGFS_ADD_FILE(ltr_config, mvm->debugfs_dir, 0200);

	debugfs_create_bool("enable_scan_iteration_notif", 0600,
			    mvm->debugfs_dir, &mvm->scan_iter_notif_enabled);
	debugfs_create_bool("drop_bcn_ap_mode", 0600, mvm->debugfs_dir,
			    &mvm->drop_bcn_ap_mode);

	MVM_DEBUGFS_ADD_FILE(uapsd_noagg_bssids, mvm->debugfs_dir, 0400);

#ifdef CPTCFG_IWLMVM_ADVANCED_QUOTA_MGMT
	MVM_DEBUGFS_ADD_FILE(quota_status, mvm->debugfs_dir, 0400);
#endif

#ifdef CONFIG_PM_SLEEP
	MVM_DEBUGFS_ADD_FILE(d3_test, mvm->debugfs_dir, 0400);
	debugfs_create_bool("d3_wake_sysassert", 0600, mvm->debugfs_dir,
			    &mvm->d3_wake_sysassert);
	debugfs_create_u32("last_netdetect_scans", 0400, mvm->debugfs_dir,
			   &mvm->last_netdetect_scans);
#endif

	debugfs_create_u8("ps_disabled", 0400, mvm->debugfs_dir,
			  &mvm->ps_disabled);
	debugfs_create_blob("nvm_hw", 0400, mvm->debugfs_dir,
			    &mvm->nvm_hw_blob);
	debugfs_create_blob("nvm_sw", 0400, mvm->debugfs_dir,
			    &mvm->nvm_sw_blob);
	debugfs_create_blob("nvm_calib", 0400, mvm->debugfs_dir,
			    &mvm->nvm_calib_blob);
	debugfs_create_blob("nvm_prod", 0400, mvm->debugfs_dir,
			    &mvm->nvm_prod_blob);
	debugfs_create_blob("nvm_phy_sku", 0400, mvm->debugfs_dir,
			    &mvm->nvm_phy_sku_blob);
	debugfs_create_blob("nvm_reg", S_IRUSR,
			    mvm->debugfs_dir, &mvm->nvm_reg_blob);

#ifdef CPTCFG_IWLWIFI_THERMAL_DEBUGFS
	debugfs_create_u32("ct_kill_exit", 0600,
			   mvm->debugfs_dir,
			   &tt_params->ct_kill_exit);
	debugfs_create_u32("ct_kill_entry", 0600,
			   mvm->debugfs_dir,
			   &tt_params->ct_kill_entry);
	debugfs_create_u32("ct_kill_duration", 0600,
			   mvm->debugfs_dir,
			   &tt_params->ct_kill_duration);
	debugfs_create_u32("dynamic_smps_entry", 0600,
			   mvm->debugfs_dir,
			   &tt_params->dynamic_smps_entry);
	debugfs_create_u32("dynamic_smps_exit", 0600,
			   mvm->debugfs_dir,
			   &tt_params->dynamic_smps_exit);
	debugfs_create_u32("tx_protection_entry", 0600,
			   mvm->debugfs_dir,
			   &tt_params->tx_protection_entry);
	debugfs_create_u32("tx_protection_exit", 0600,
			   mvm->debugfs_dir,
			   &tt_params->tx_protection_exit);
#endif

	debugfs_create_file("mem", 0600, mvm->debugfs_dir, mvm,
			    &iwl_dbgfs_mem_ops);

	/*
	 * Create a symlink with mac80211. It will be removed when mac80211
	 * exists (before the opmode exists which removes the target.)
	 */
	if (!IS_ERR(mvm->debugfs_dir)) {
		char buf[100];

		snprintf(buf, 100, "../../%pd2", mvm->debugfs_dir->d_parent);
		debugfs_create_symlink("iwlwifi", mvm->hw->wiphy->debugfsdir,
				       buf);
	}
}

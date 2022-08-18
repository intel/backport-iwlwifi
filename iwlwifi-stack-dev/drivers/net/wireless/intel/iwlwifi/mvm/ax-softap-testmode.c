// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2017 Intel Deutschland GmbH
 * Copyright (C) 2021 - 2022 Intel Corporation
 */
#include "debugfs.h"
#include "mvm.h"
#include "fw/api/ax-softap-testmode.h"
#include <net/mac80211.h>

#define DL_BASIC_CMD_SIZE 0x104
#define DL_MU_BAR_CMD_SIZE 0x80
#define UL_CMD_SIZE 0xa0

static ssize_t
iwl_dbgfs_ax_softap_testmode_dl_basic_write(struct iwl_mvm *mvm,
					    char *buf, size_t count,
					    loff_t *ppos)
{
	int ret;
	u32 status;

	if (count != DL_BASIC_CMD_SIZE) {
		IWL_ERR(mvm,
			"Bad size for softap dl basic cmd (%zd) should be (%d)\n",
			count, DL_BASIC_CMD_SIZE);
		return -EINVAL;
	}

	status = 0;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd_pdu_status(mvm,
					  WIDE_ID(DATA_PATH_GROUP, AX_SOFTAP_TESTMODE_DL_BASIC),
					  count, buf, &status);
	mutex_unlock(&mvm->mutex);
	if (ret) {
		IWL_ERR(mvm, "Failed to send softap dl basic cmd (%d)\n",
			ret);
		return ret;
	}

	if (status) {
		IWL_ERR(mvm, "softap dl basic cmd failed (%d)\n",
			status);
		return -EIO;
	}

	return count;
}

static ssize_t
iwl_dbgfs_ax_softap_testmode_dl_mu_bar_write(struct iwl_mvm *mvm,
					     char *buf, size_t count,
					     loff_t *ppos)
{
	int ret;
	u32 status;

	if (count != DL_MU_BAR_CMD_SIZE) {
		IWL_ERR(mvm,
			"Bad size for softap dl mu bar cmd (%zd) should be (%d)\n",
			count, DL_MU_BAR_CMD_SIZE);
		return -EINVAL;
	}

	status = 0;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd_pdu_status(mvm,
					  WIDE_ID(DATA_PATH_GROUP, AX_SOFTAP_TESTMODE_DL_MU_BAR),
					  count, buf, &status);
	mutex_unlock(&mvm->mutex);
	if (ret) {
		IWL_ERR(mvm, "Failed to send softap dl mu bar cmd (%d)\n",
			ret);
		return ret;
	}

	if (status) {
		IWL_ERR(mvm, "softap dl mu bar cmd failed (%d)\n",
			status);
		return -EIO;
	}

	return count;
}

static ssize_t
iwl_dbgfs_ax_softap_testmode_ul_write(struct iwl_mvm *mvm,
				      char *buf, size_t count, loff_t *ppos)
{
	int ret;
	u32 status;

	if (count != UL_CMD_SIZE) {
		IWL_ERR(mvm,
			"Bad size for softap ul cmd (%zd) should be (%d)\n",
			count, UL_CMD_SIZE);
		return -EINVAL;
	}

	status = 0;

	mutex_lock(&mvm->mutex);
	ret = iwl_mvm_send_cmd_pdu_status(mvm,
					  WIDE_ID(DATA_PATH_GROUP, AX_SOFTAP_TESTMODE_UL),
					  count, buf, &status);
	mutex_unlock(&mvm->mutex);
	if (ret) {
		IWL_ERR(mvm, "Failed to send softap ul cmd (%d)\n",
			ret);
		return ret;
	}

	if (status) {
		IWL_ERR(mvm, "softap ul cmd failed (%d)\n",
			status);
		return -EIO;
	}

	return count;
}

#define MVM_DEBUGFS_WRITE_FILE_OPS(name, bufsz)				\
	_MVM_DEBUGFS_WRITE_FILE_OPS(name, bufsz, struct iwl_mvm)
#define MVM_DEBUGFS_ADD_FILE_AX_SOFTAP_TM(name, parent, mode) do {	\
		if (!debugfs_create_file(#name, mode, parent, mvm,	\
					 &iwl_dbgfs_##name##_ops))	\
			goto err;					\
	} while (0)

/* +1 for null char */
MVM_DEBUGFS_WRITE_FILE_OPS(ax_softap_testmode_dl_basic, DL_BASIC_CMD_SIZE + 1);
MVM_DEBUGFS_WRITE_FILE_OPS(ax_softap_testmode_dl_mu_bar, DL_MU_BAR_CMD_SIZE + 1);
MVM_DEBUGFS_WRITE_FILE_OPS(ax_softap_testmode_ul, UL_CMD_SIZE + 1);

static void ax_softap_testmode_add_debugfs(struct ieee80211_hw *hw,
					   struct ieee80211_vif *vif,
					   struct ieee80211_sta *sta,
					   struct dentry *dir)
{
	struct iwl_mvm *mvm = IWL_MAC80211_GET_MVM(hw);

	MVM_DEBUGFS_ADD_FILE_AX_SOFTAP_TM(ax_softap_testmode_dl_basic,
					  dir, S_IWUSR);
	MVM_DEBUGFS_ADD_FILE_AX_SOFTAP_TM(ax_softap_testmode_dl_mu_bar,
					  dir, S_IWUSR);
	MVM_DEBUGFS_ADD_FILE_AX_SOFTAP_TM(ax_softap_testmode_ul,
					  dir, S_IWUSR);
	return;
err:
	IWL_ERR(mvm, "Can't create debugfs entity\n");
}

void
iwl_mvm_ax_softap_testmode_sta_add_debugfs(struct ieee80211_hw *hw,
					   struct ieee80211_vif *vif,
					   struct ieee80211_sta *sta,
					   struct dentry *dir)
{
	if (fw_has_capa(&IWL_MAC80211_GET_MVM(hw)->fw->ucode_capa,
			IWL_UCODE_TLV_CAPA_AX_SAP_TM_V2))
		ax_softap_testmode_add_debugfs(hw, vif, sta, dir);
}

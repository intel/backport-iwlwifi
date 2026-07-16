// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 Intel Corporation
 */

#include <net/mac80211.h>

#include "mld.h"
#include "hcmd.h"
#include "debugfs.h"
#include "ax-softap-testmode.h"
#include "fw/api/ax-softap-testmode.h"

static int
iwl_mld_send_cmd_status(struct iwl_mld *mld, u32 id,
			size_t count, const char *buf)
{
	struct iwl_host_cmd hcmd = {
		.id = id,
		.flags = CMD_WANT_SKB,
		.data = { buf },
		.len[0] = count,
	};
	int ret = 0;
	u32 status;

	if (!mld->fw_status.running)
		return -EIO;

	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (WARN_ON(ret))
		return ret;

	if (WARN_ON(iwl_rx_packet_payload_len(hcmd.resp_pkt) != sizeof(status))) {
		ret = -EINVAL;
		goto out;
	}

	status = le32_to_cpup((const __le32 *)hcmd.resp_pkt->data);

	if (WARN_ON(status))
		ret = -EIO;

out:
	iwl_free_resp(&hcmd);
	return ret;
}

#define DL_BASIC_CMD_SIZE 0x104
static ssize_t
iwl_dbgfs_ax_softap_testmode_dl_basic_write(struct iwl_mld *mld,
					    char *buf, size_t count)
{
	if (count != DL_BASIC_CMD_SIZE) {
		IWL_ERR(mld,
			"Bad size for softap dl basic cmd (%zd) should be (%d)\n",
			count, DL_BASIC_CMD_SIZE);
		return -EINVAL;
	}

	return iwl_mld_send_cmd_status(mld,
				      WIDE_ID(DATA_PATH_GROUP,
					      AX_SOFTAP_TESTMODE_DL_BASIC),
				      count, buf) ?: count;
}

#define DL_MU_BAR_CMD_SIZE 0x80
static ssize_t
iwl_dbgfs_ax_softap_testmode_dl_mu_bar_write(struct iwl_mld *mld,
					     char *buf, size_t count)
{
	if (count != DL_MU_BAR_CMD_SIZE) {
		IWL_ERR(mld,
			"Bad size for softap dl mu bar cmd (%zd) should be (%d)\n",
			count, DL_MU_BAR_CMD_SIZE);
		return -EINVAL;
	}

	return iwl_mld_send_cmd_status(mld,
				      WIDE_ID(DATA_PATH_GROUP,
					      AX_SOFTAP_TESTMODE_DL_MU_BAR),
				      count, buf) ?: count;
}

#define UL_CMD_SIZE 0xa0
static ssize_t
iwl_dbgfs_ax_softap_testmode_ul_write(struct iwl_mld *mld,
				      char *buf, size_t count)
{
	if (count != UL_CMD_SIZE) {
		IWL_ERR(mld,
			"Bad size for softap ul cmd (%zd) should be (%d)\n",
			count, UL_CMD_SIZE);
		return -EINVAL;
	}

	return iwl_mld_send_cmd_status(mld,
				       WIDE_ID(DATA_PATH_GROUP,
					       AX_SOFTAP_TESTMODE_UL),
				       count, buf) ?: count;
}

static ssize_t
iwl_dbgfs_ax_softap_client_testmode_write(struct iwl_mld *mld,
					  char *buf, size_t count)
{
	struct ax_softap_client_testmode_cmd cmd = {};
	bool is_enabled;
	int ret;

	ret = kstrtobool(buf, &is_enabled);
	if (ret) {
		IWL_ERR(mld, "Invalid softap client debugfs value (%d)\n", ret);
		return ret;
	}

	if (!mld->fw_status.running)
		return -EIO;

	cmd.enable = is_enabled;

	return iwl_mld_send_cmd_pdu(mld,
				    WIDE_ID(DATA_PATH_GROUP,
					    AX_SOFTAP_CLIENT_TESTMODE),
				    &cmd) ?: count;
}
/* +1 for null char */
WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(ax_softap_testmode_dl_basic,
				 DL_BASIC_CMD_SIZE + 1);
WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(ax_softap_testmode_dl_mu_bar,
				 DL_MU_BAR_CMD_SIZE + 1);
WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(ax_softap_testmode_ul, UL_CMD_SIZE + 1);
WIPHY_DEBUGFS_WRITE_FILE_OPS_MLD(ax_softap_client_testmode, 8);

#define MLD_DEBUGFS_ADD_FILE_ALIAS(alias, name, parent, mode) do {	\
	debugfs_create_file(alias, mode, parent, mld,			\
			    &iwl_dbgfs_##name##_ops);			\
	} while (0)
#define MLD_DEBUGFS_ADD_FILE(name, parent, mode)			\
	MLD_DEBUGFS_ADD_FILE_ALIAS(#name, name, parent, mode)

void
iwl_mld_ax_softap_testmode_sta_add_debugfs(struct ieee80211_hw *hw,
					   struct ieee80211_vif *vif,
					   struct ieee80211_sta *sta,
					   struct dentry *dir)
{
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	if (!fw_has_capa(&mld->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_AX_SAP_TM_V2))
		return;

	MLD_DEBUGFS_ADD_FILE(ax_softap_testmode_dl_basic, dir, 0200);
	MLD_DEBUGFS_ADD_FILE(ax_softap_testmode_dl_mu_bar, dir, 0200);
	MLD_DEBUGFS_ADD_FILE(ax_softap_testmode_ul, dir, 0200);
	MLD_DEBUGFS_ADD_FILE(ax_softap_client_testmode, mld->debugfs_dir, 0200);
}

/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
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
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
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
#include <net/cfg80211.h>

#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "fw/img.h"
#include "iwl-debug.h"
#include "iwl-phy-db.h"
#include "iwl-io.h"
#include "iwl-prph.h"
#include "iwl-nvm-parse.h"
#include "fw/acpi.h"
#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
#include "fw/testmode.h"
#endif
#include "fw-api.h"
#include "fmac.h"
#include "fw/dbg.h"

void iwl_fmac_mfu_assert_dump_notif(struct iwl_fmac *fmac,
				    struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mfu_assert_dump_notif *mfu_dump_notif = (void *)pkt->data;
	__le32 *dump_data = mfu_dump_notif->data;
	int n_words = le32_to_cpu(mfu_dump_notif->data_size) / sizeof(__le32);
	int i;

	if (mfu_dump_notif->index_num == 0)
		IWL_INFO(fmac, "MFUART assert id 0x%x occurred\n",
			 mfu_dump_notif->assert_id);

	for (i = 0; i < n_words; i++)
		IWL_DEBUG_INFO(fmac,
			       "MFUART assert dump, dword %u: 0x%08x\n",
			       le16_to_cpu(mfu_dump_notif->index_num) *
			       n_words + i,
			       le32_to_cpu(dump_data[i]));
}

struct iwl_alive_data {
	bool valid;
	u32 scd_base_addr;
};

static bool iwl_fmac_alive_fn(struct iwl_notif_wait_data *notif_wait,
			      struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_fmac *fmac =
		container_of(notif_wait, struct iwl_fmac, notif_wait);
	struct iwl_alive_data *alive_data = data;
	struct iwl_umac_alive *umac;
	struct iwl_lmac_alive *lmac1;
	struct iwl_lmac_alive *lmac2 = NULL;
	__le16 status;
	u32 lmac_error_event_table, umac_error_event_table;

	if (iwl_rx_packet_payload_len(pkt) == sizeof(struct mvm_alive_resp)) {
		struct mvm_alive_resp *palive = (void *)pkt->data;

		umac = &palive->umac_data;
		lmac1 = &palive->lmac_data[0];
		lmac2 = &palive->lmac_data[1];
		status = palive->status;
	} else if (iwl_rx_packet_payload_len(pkt) ==
			sizeof(struct mvm_alive_resp_v3)) {
		struct mvm_alive_resp_v3 *palive = (void *)pkt->data;

		umac = &palive->umac_data;
		lmac1 = &palive->lmac_data;
		status = palive->status;
	} else {
		WARN(1, "unexpected size %d\n", iwl_rx_packet_payload_len(pkt));
		/* get timeout later */
		return false;
	}

	lmac_error_event_table =
		le32_to_cpu(lmac1->dbg_ptrs.error_event_table_ptr);
	iwl_fw_lmac1_set_alive_err_table(fmac->trans, lmac_error_event_table);

	if (lmac2)
		fmac->trans->dbg.lmac_error_event_table[1] =
			le32_to_cpu(lmac2->dbg_ptrs.error_event_table_ptr);
	alive_data->scd_base_addr = le32_to_cpu(lmac1->dbg_ptrs.scd_base_ptr);

	umac_error_event_table = le32_to_cpu(umac->dbg_ptrs.error_info_addr);
	iwl_fw_umac_set_alive_err_table(fmac->trans, umac_error_event_table);

	alive_data->valid = status == cpu_to_le16(IWL_ALIVE_STATUS_OK);

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
	iwl_tm_set_fw_ver(fmac->trans, le32_to_cpu(lmac1->ucode_major),
			  le32_to_cpu(lmac1->ucode_minor));
#endif
	IWL_DEBUG_FW(fmac,
		     "Alive firmware status 0x%04x revision 0x%01x 0x%01x\n",
		     le16_to_cpu(status), lmac1->ver_type,
		     lmac1->ver_subtype);

	if (lmac2)
		IWL_DEBUG_FW(fmac, "Alive ucode CDB\n");

	IWL_DEBUG_FW(fmac,
		     "UMAC version: Major - 0x%x, Minor - 0x%x\n",
		     le32_to_cpu(umac->umac_major),
		     le32_to_cpu(umac->umac_minor));

	iwl_fwrt_update_fw_versions(&fmac->fwrt, lmac1, umac);

	return true;
}

#define FW_ALIVE_TIMEOUT	(HZ * CPTCFG_IWL_TIMEOUT_FACTOR)
static int iwl_load_fw_wait_alive(struct iwl_fmac *fmac,
				  enum iwl_ucode_type ucode_type)
{
	struct iwl_notification_wait alive_wait;
	struct iwl_alive_data alive_data = {0};
	const struct fw_img *fw;
	static const u16 alive_cmd[] = { MVM_ALIVE };
	int ret;

	fw = iwl_get_ucode_image(fmac->fw, ucode_type);
	if (WARN_ON(!fw))
		return -EINVAL;

	iwl_init_notification_wait(&fmac->notif_wait, &alive_wait,
				   alive_cmd, ARRAY_SIZE(alive_cmd),
				   iwl_fmac_alive_fn, &alive_data);

	ret = iwl_trans_start_fw(fmac->trans, fw,
				 ucode_type == IWL_UCODE_INIT ||
					iwl_fmac_has_unified_ucode(fmac));
	if (ret)
		goto remove_notif;

	/*
	 * Some things may run in the background now, but we
	 * just wait for the ALIVE notification here.
	 */
	ret = iwl_wait_notification(&fmac->notif_wait, &alive_wait,
				    FW_ALIVE_TIMEOUT);

	if (ret) {
		struct iwl_trans *trans = fmac->trans;

		if (ret == -ETIMEDOUT)
			iwl_fw_dbg_error_collect(&fmac->fwrt,
						 FW_DBG_TRIGGER_ALIVE_TIMEOUT);

		if (trans->cfg->gen2)
			IWL_ERR(fmac,
				"SecBoot CPU1 Status: 0x%x, CPU2 Status: 0x%x\n",
				iwl_read_umac_prph(trans, UMAG_SB_CPU_1_STATUS),
				iwl_read_umac_prph(trans,
						   UMAG_SB_CPU_2_STATUS));
		else
			IWL_ERR(fmac,
				"SecBoot CPU1 Status: 0x%x, CPU2 Status: 0x%x\n",
				iwl_read_prph(trans, SB_CPU_1_STATUS),
				iwl_read_prph(trans, SB_CPU_2_STATUS));
		return ret;
	}

	if (!alive_data.valid) {
		IWL_ERR(fmac, "Loaded ucode is not valid!\n");
		return -EIO;
	}
	iwl_fw_set_current_image(&fmac->fwrt, ucode_type);

	iwl_trans_fw_alive(fmac->trans, alive_data.scd_base_addr);

	ret = iwl_init_paging(&fmac->fwrt, ucode_type);
	if (ret)
		return ret;

#ifdef CPTCFG_CFG80211_DEBUGFS
	if (ucode_type == IWL_UCODE_REGULAR) {
		iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
					 IWL_FMAC_CONFIG_INTERNAL_CMD_TO_HOST,
					 fmac->internal_cmd_to_host);
		iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
					 IWL_FMAC_CONFIG_DEBUG_LEVEL,
					 fmac->fw_debug_level);
	}
#endif
#ifdef CPTCFG_IWLWIFI_DEBUGFS
	iwl_fw_set_dbg_rec_on(&fmac->fwrt);
#endif

	return 0;

remove_notif:
	iwl_remove_notification(&fmac->notif_wait, &alive_wait);
	return ret;
}

static int iwl_fmac_send_phy_cfg_cmd(struct iwl_fmac *fmac)
{
	struct iwl_phy_cfg_cmd phy_cfg_cmd;
	enum iwl_ucode_type ucode_type = fmac->fwrt.cur_fw_img;
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	u32 override_mask, flow_override, flow_src;
	u32 event_override, event_src;
	const struct iwl_tlv_calib_ctrl *default_calib =
		&fmac->fw->default_calib[ucode_type];
#endif

	/* Set parameters */
	phy_cfg_cmd.phy_cfg = cpu_to_le32(iwl_fmac_get_phy_config(fmac));

	/* set flags extra PHY configuration flags from the device's cfg */
	phy_cfg_cmd.phy_cfg |= cpu_to_le32(fmac->cfg->extra_phy_cfg_flags);

	phy_cfg_cmd.calib_control.event_trigger =
		fmac->fw->default_calib[ucode_type].event_trigger;
	phy_cfg_cmd.calib_control.flow_trigger =
		fmac->fw->default_calib[ucode_type].flow_trigger;

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	override_mask = fmac->trans->dbg_cfg.MVM_CALIB_OVERRIDE_CONTROL;
	if (override_mask) {
		struct iwl_dbg_cfg *dbg_cfg = &fmac->trans->dbg_cfg;

		IWL_DEBUG_INFO(fmac,
			       "calib settings overridden by user, control=0x%x\n",
			       override_mask);

		switch (ucode_type) {
		case IWL_UCODE_INIT:
			flow_override = dbg_cfg->MVM_CALIB_INIT_FLOW;
			event_override = dbg_cfg->MVM_CALIB_INIT_EVENT;
			IWL_DEBUG_CALIB(fmac,
					"INIT: flow_override %x, event_override %x\n",
					flow_override, event_override);
			break;
		case IWL_UCODE_REGULAR:
			flow_override = dbg_cfg->MVM_CALIB_D0_FLOW;
			event_override = dbg_cfg->MVM_CALIB_D0_EVENT;
			IWL_DEBUG_CALIB(fmac,
					"REGULAR: flow_override %x, event_override %x\n",
					flow_override, event_override);
			break;
		case IWL_UCODE_WOWLAN:
			flow_override = dbg_cfg->MVM_CALIB_D3_FLOW;
			event_override = dbg_cfg->MVM_CALIB_D3_EVENT;
			IWL_DEBUG_CALIB(fmac,
					"WOWLAN: flow_override %x, event_override %x\n",
					flow_override, event_override);
			break;
		default:
			IWL_ERR(fmac, "ERROR: calib case isn't valid\n");
			flow_override = 0;
			event_override = 0;
			break;
		}

		IWL_DEBUG_CALIB(fmac, "override_mask %x\n", override_mask);

		/* find the new calib setting for the flow calibrations */
		flow_src = le32_to_cpu(default_calib->flow_trigger);
		IWL_DEBUG_CALIB(fmac, "flow_src %x\n", flow_src);

		flow_override &= override_mask;
		flow_src &= ~override_mask;
		flow_override |= flow_src;

		phy_cfg_cmd.calib_control.flow_trigger =
			cpu_to_le32(flow_override);
		IWL_DEBUG_CALIB(fmac, "new flow calib setting = %x\n",
				flow_override);

		/* find the new calib setting for the event calibrations */
		event_src = le32_to_cpu(default_calib->event_trigger);
		IWL_DEBUG_CALIB(fmac, "event_src %x\n", event_src);

		event_override &= override_mask;
		event_src &= ~override_mask;
		event_override |= event_src;

		phy_cfg_cmd.calib_control.event_trigger =
			cpu_to_le32(event_override);
		IWL_DEBUG_CALIB(fmac, "new event calib setting = %x\n",
				event_override);
	}
#endif
	IWL_DEBUG_INFO(fmac, "Sending Phy CFG command: 0x%x\n",
		       phy_cfg_cmd.phy_cfg);

	return iwl_fmac_send_cmd_pdu(fmac, PHY_CONFIGURATION_CMD, 0,
				sizeof(phy_cfg_cmd), &phy_cfg_cmd);
}

struct ieee80211_regdomain *
iwl_fmac_set_regdom(struct iwl_fmac *fmac, const char *mcc,
		    enum iwl_fmac_mcc_source src_id)
{
	struct iwl_fmac_reg_cmd cmd = {
		.mcc = cpu_to_le16(mcc[0] << 8 | mcc[1]),
		.source_id = src_id,
	};
	struct iwl_host_cmd hcmd = {
		.flags = CMD_WANT_SKB,
		.id = iwl_cmd_id(FMAC_REG_CFG, FMAC_GROUP, 0),
		.data = { &cmd, },
		.len = { sizeof(cmd), },
	};
	struct iwl_fmac_reg_resp *rsp;
	struct ieee80211_regdomain *regd = NULL;
	u32 rsp_size;
	int ret;

	IWL_DEBUG_LAR(fmac, "send MCC update to FW with '%c%c' src = %d\n",
		      mcc[0], mcc[1], src_id);
	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	if (ret)
		return NULL;

	if (!hcmd.resp_pkt)
		return NULL;

	rsp_size = iwl_rx_packet_payload_len(hcmd.resp_pkt);
	rsp = (void *)hcmd.resp_pkt->data;
	if (rsp_size < sizeof(*rsp) ||
	    rsp_size != sizeof(*rsp) + sizeof(__le32) *
			le32_to_cpu(rsp->n_channels))
		goto cleanup;

	regd = iwl_parse_nvm_mcc_info(fmac->dev, fmac->cfg,
				      __le32_to_cpu(rsp->n_channels),
				      rsp->channels,
				      __le16_to_cpu(rsp->mcc), 0);
	if (IS_ERR_OR_NULL(regd)) {
		IWL_ERR(fmac, "Could not parse update from FW %d\n",
			PTR_ERR_OR_ZERO(regd));
		regd = NULL;
		goto cleanup;
	}
	IWL_DEBUG_LAR(fmac,
		      "setting alpha2 from FW to %s (0x%x, 0x%x) src=%d\n",
		      regd->alpha2, regd->alpha2[0], regd->alpha2[1],
		      rsp->source_id);

	/* save the last source id for FW reconfig */
	fmac->mcc_src = rsp->source_id;

cleanup:
	iwl_free_resp(&hcmd);
	return regd;
}

static int iwl_fmac_config_prev_regdom(struct iwl_fmac *fmac)
{
	int ret;
	struct ieee80211_regdomain *regd;
	const struct ieee80211_regdomain *r =
				rtnl_dereference(wiphy_from_fmac(fmac)->regd);

	if (!r)
		return -ENOENT;

	/* set our last stored MCC and source */
	regd = iwl_fmac_set_regdom(fmac, r->alpha2, fmac->mcc_src);
	if (IS_ERR_OR_NULL(regd))
		return -EIO;

	ret = regulatory_set_wiphy_regd_sync_rtnl(wiphy_from_fmac(fmac), regd);

	kfree(regd);
	return ret;
}

static int iwl_fmac_config_regulatory(struct iwl_fmac *fmac)
{
	char mcc[3] = "ZZ"; /* default regdom */
	enum iwl_fmac_mcc_source src_id = IWL_FMAC_MCC_SOURCE_GET_CURRENT;
	struct ieee80211_regdomain *regd;
	int ret;

	/* we do not support FMAC without LAR */
	if (iwlwifi_mod_params.lar_disable ||
	    !fw_has_capa(&fmac->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_LAR_SUPPORT)) {
		IWL_ERR(fmac, "Error: LAR can't be disabled in FMAC FW\n");
		return -ENOTSUPP;
	}

	/* reset to existing regdom during FW restart */
	ret = iwl_fmac_config_prev_regdom(fmac);
	if (ret != -ENOENT)
		return ret;

	/* BIOS overrides the default configuration */
	if (!iwl_acpi_get_mcc(fmac->dev, mcc)) {
		IWL_DEBUG_LAR(fmac, "Setting MCC from BIOS to %c%c\n",
			      mcc[0], mcc[1]);
		src_id = IWL_FMAC_MCC_SOURCE_BIOS;
	}

	regd = iwl_fmac_set_regdom(fmac, mcc, src_id);
	if (IS_ERR_OR_NULL(regd))
		goto cleanup;

	ret = regulatory_set_wiphy_regd_sync_rtnl(wiphy_from_fmac(fmac), regd);
	if (ret) {
		IWL_ERR(fmac, "Could not set regdom to cfg80211\n");
		goto cleanup;
	}

cleanup:
	if (!IS_ERR_OR_NULL(regd))
		kfree(regd);

	return ret;
}

static bool iwl_fmac_wait_phy_db_entry(struct iwl_notif_wait_data *notif_wait,
				       struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_phy_db *phy_db = data;

	if (pkt->hdr.cmd != CALIB_RES_NOTIF_PHY_DB) {
		WARN_ON(pkt->hdr.cmd != INIT_COMPLETE_NOTIF);
		return true;
	}

	WARN_ON(iwl_phy_db_set_section(phy_db, pkt));

	return false;
}

#define FW_CALIB_TIMEOUT (2 * HZ * CPTCFG_IWL_TIMEOUT_FACTOR)
static int _iwl_fmac_run_init_fw(struct iwl_fmac *fmac, bool read_nvm)
{
	struct iwl_notification_wait calib_wait;
	static const u16 init_complete[] = {
		INIT_COMPLETE_NOTIF,
		CALIB_RES_NOTIF_PHY_DB
	};
	int ret;

	lockdep_assert_held(&fmac->mutex);

	if (WARN_ON_ONCE(fmac->rfkill_safe_init_done))
		return 0;

	fmac->rfkill_safe_init_done = false;

	iwl_init_notification_wait(&fmac->notif_wait,
				   &calib_wait,
				   init_complete,
				   ARRAY_SIZE(init_complete),
				   iwl_fmac_wait_phy_db_entry,
				   fmac->phy_db);

	ret = iwl_load_fw_wait_alive(fmac, IWL_UCODE_INIT);
	if (ret) {
		IWL_ERR(fmac, "Failed to start INIT firmware: %d\n", ret);
		goto remove_notif;
	}

	/* read NVM */
	if (read_nvm) {
		ret = iwl_fmac_nvm_init(fmac, true);
		if (ret)
			goto remove_notif;
	}

	/* In case we read the NVM from external file, load it to the NIC */
	if (fmac->nvm_file_name)
		iwl_fmac_load_nvm_to_nic(fmac);

	if (iwl_fmac_is_radio_killed(fmac)) {
		IWL_DEBUG_RF_KILL(fmac,
				  "jump over all phy activities due to RF kill\n");
		goto remove_notif;
	}
	fmac->rfkill_safe_init_done = true;

	ret = iwl_fmac_send_phy_cfg_cmd(fmac);
	if (ret) {
		IWL_ERR(fmac, "Failed to run INIT calibrations: %d\n",
			ret);
		goto remove_notif;
	}

	/*
	 * Some things may run in the background now, but we
	 * just wait for the calibration complete notification.
	 */
	ret = iwl_wait_notification(&fmac->notif_wait, &calib_wait,
				    FW_CALIB_TIMEOUT);
	if (!ret)
		goto out;

	if (iwl_fmac_is_radio_killed(fmac)) {
		IWL_DEBUG_RF_KILL(fmac, "RFKILL while calibrating.\n");
		ret = 0;
	} else {
		IWL_ERR(fmac, "Failed to run INIT calibrations: %d\n", ret);
	}

	goto out;

remove_notif:
	iwl_remove_notification(&fmac->notif_wait, &calib_wait);
out:
	fmac->rfkill_safe_init_done = false;

	return ret;
}

static int iwl_send_rss_cfg_cmd(struct iwl_fmac *fmac)
{
	int i;
	struct iwl_rss_config_cmd cmd = {
		.flags = cpu_to_le32(IWL_RSS_ENABLE),
		.hash_mask = BIT(IWL_RSS_HASH_TYPE_IPV4_TCP) |
			     BIT(IWL_RSS_HASH_TYPE_IPV4_UDP) |
			     BIT(IWL_RSS_HASH_TYPE_IPV4_PAYLOAD) |
			     BIT(IWL_RSS_HASH_TYPE_IPV6_TCP) |
			     BIT(IWL_RSS_HASH_TYPE_IPV6_UDP) |
			     BIT(IWL_RSS_HASH_TYPE_IPV6_PAYLOAD),
	};
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(RSS_CONFIG_CMD, LEGACY_GROUP, 0),
		.data = { &cmd, },
		.len = { sizeof(cmd), },
	};

	/* TODO - remove 22000 disablement when we have RXQ config API */
	if (fmac->cfg->device_family >= IWL_DEVICE_FAMILY_22000)
		return 0;

	if (fmac->trans->num_rx_queues == 1)
		return 0;

	/* Do not direct RSS traffic to Q 0 which is our fallback queue */
	for (i = 0; i < ARRAY_SIZE(cmd.indirection_table); i++)
		cmd.indirection_table[i] =
			1 + (i % (fmac->trans->num_rx_queues - 1));

	netdev_rss_key_fill(cmd.secret_key, sizeof(cmd.secret_key));

	return iwl_fmac_send_cmd(fmac, &hcmd);
}

int iwl_fmac_send_config_cmd(struct iwl_fmac *fmac,
			     u8 vif_id, enum iwl_fmac_config_id config_id,
			     const void *data, u16 len)
{
	struct iwl_fmac_config_cmd *cmd;
	u16 cmd_len = sizeof(*cmd) + len;
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(FMAC_CONFIG, FMAC_GROUP, 0),
		.len = { cmd_len },
	};
	int ret;

	if (WARN_ON(len & 0x3))
		return -EINVAL;

	cmd = kzalloc(cmd_len, GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	hcmd.data[0] = cmd;

	cmd->vif_id = vif_id;
	cmd->config_id = cpu_to_le16(config_id);
	cmd->len = cpu_to_le16(len);
	memcpy(cmd->data, data, len);

	ret = iwl_fmac_send_cmd(fmac, &hcmd);

	kfree(cmd);

	return ret;
}

static bool iwl_wait_init_complete(struct iwl_notif_wait_data *notif_wait,
				   struct iwl_rx_packet *pkt, void *data)
{
	WARN_ON(pkt->hdr.cmd != INIT_COMPLETE_NOTIF);

	return true;
}

static int iwl_fmac_run_unified_ucode(struct iwl_fmac *fmac, bool read_nvm)
{
	struct iwl_notification_wait init_wait;
	struct iwl_nvm_access_complete_cmd nvm_complete = {};
	struct iwl_init_extended_cfg_cmd init_cfg = {
		.init_flags = cpu_to_le32(BIT(IWL_INIT_NVM)),
	};
	static const u16 init_complete[] = {
		INIT_COMPLETE_NOTIF,
	};
	int ret;

	lockdep_assert_held(&fmac->mutex);

	fmac->rfkill_safe_init_done = false;

	iwl_init_notification_wait(&fmac->notif_wait, &init_wait,
				   init_complete, ARRAY_SIZE(init_complete),
				   iwl_wait_init_complete, NULL);

	iwl_fw_dbg_apply_point(&fmac->fwrt, IWL_FW_INI_APPLY_EARLY);

	/* Will also start the device */
	ret = iwl_load_fw_wait_alive(fmac, IWL_UCODE_REGULAR);
	if (ret) {
		IWL_ERR(fmac, "Failed to start RT ucode: %d\n", ret);
		goto error;
	}
	iwl_fw_dbg_apply_point(&fmac->fwrt, IWL_FW_INI_APPLY_AFTER_ALIVE);

	/*
	 * Send init config command to mark that we are sending NVM access
	 * commands
	 */
	ret = iwl_fmac_send_cmd_pdu(fmac, WIDE_ID(SYSTEM_GROUP,
						  INIT_EXTENDED_CFG_CMD),
				    CMD_SEND_IN_RFKILL,
				    sizeof(init_cfg), &init_cfg);
	if (ret) {
		IWL_ERR(fmac, "Failed to run init config command: %d\n",
			ret);
		goto error;
	}

	/* In case we read the NVM from external file, load it to the NIC */
	if (fmac->nvm_file_name) {
		iwl_read_external_nvm(fmac->trans, fmac->nvm_file_name,
				      fmac->nvm_sections);
		iwl_fmac_load_nvm_to_nic(fmac);
	}

	ret = iwl_fmac_send_cmd_pdu(fmac, WIDE_ID(REGULATORY_AND_NVM_GROUP,
						  NVM_ACCESS_COMPLETE),
				    CMD_SEND_IN_RFKILL,
				    sizeof(nvm_complete), &nvm_complete);
	if (ret) {
		IWL_ERR(fmac, "Failed to run complete NVM access: %d\n",
			ret);
		goto error;
	}

	/* We wait for the INIT complete notification */
	ret = iwl_wait_notification(&fmac->notif_wait, &init_wait,
				    FW_ALIVE_TIMEOUT);
	if (ret)
		return ret;

	/* Read the NVM only at driver load time, no need to do this twice */
	if (read_nvm) {
		fmac->nvm_data = iwl_get_nvm(fmac->trans, fmac->fw);
		if (IS_ERR(fmac->nvm_data)) {
			ret = PTR_ERR(fmac->nvm_data);
			fmac->nvm_data = NULL;
			IWL_ERR(fmac, "Failed to read NVM: %d\n", ret);
			return ret;
		}
	}

	fmac->rfkill_safe_init_done = true;

	return 0;

error:
	iwl_remove_notification(&fmac->notif_wait, &init_wait);
	return ret;
}

int iwl_fmac_run_init_fw(struct iwl_fmac *fmac)
{
	if (iwl_fmac_has_new_tx_api(fmac))
		return iwl_fmac_run_unified_ucode(fmac, true);

	return _iwl_fmac_run_init_fw(fmac, true);
}

static int iwl_fmac_init_triggers(struct iwl_fmac *fmac)
{
	struct iwl_fmac_trigger_cmd *cmd;
	enum iwl_fmac_vif_type cmd_vif_type;
	enum iwl_fw_dbg_trigger_vif_type trig_vif_type;
	size_t cmd_len;
	size_t trigger_len;
	int ret = 0, i;

	for (i = 0; i < ARRAY_SIZE(fmac->fw->dbg.trigger_tlv); i++) {
		if (!fmac->fw->dbg.trigger_tlv[i])
			continue;

		trigger_len = fmac->fw->dbg.trigger_tlv_len[i] -
			sizeof(*fmac->fw->dbg.trigger_tlv[i]);
		cmd_len = trigger_len + sizeof(*cmd);
		cmd = kzalloc(cmd_len, GFP_KERNEL);
		if (!cmd)
			return -ENOMEM;
		cmd->len = cpu_to_le32(trigger_len);
		cmd->id = fmac->fw->dbg.trigger_tlv[i]->id;
		trig_vif_type =
			le32_to_cpu(fmac->fw->dbg.trigger_tlv[i]->vif_type);

		switch (trig_vif_type) {
		case IWL_FW_DBG_CONF_VIF_ANY:
			cmd_vif_type = IWL_FMAC_IFTYPE_ANY;
			break;
		case IWL_FW_DBG_CONF_VIF_STATION:
			cmd_vif_type = IWL_FMAC_IFTYPE_MGD;
			break;
		case IWL_FW_DBG_CONF_VIF_P2P_CLIENT:
			cmd_vif_type = IWL_FMAC_IFTYPE_P2P_CLIENT;
			break;
		case IWL_FW_DBG_CONF_VIF_P2P_GO:
			cmd_vif_type = IWL_FMAC_IFTYPE_P2P_GO;
			break;
		case IWL_FW_DBG_CONF_VIF_P2P_DEVICE:
			cmd_vif_type = IWL_FMAC_IFTYPE_P2P_DEVICE;
			break;
		default:
			IWL_ERR(fmac, "Invalid vif type %d\n", trig_vif_type);
			kfree(cmd);
			return -EINVAL;
		}
		cmd->vif_type = cpu_to_le32(cmd_vif_type);
		memcpy(&cmd->data, fmac->fw->dbg.trigger_tlv[i]->data,
		       trigger_len);
		ret = iwl_fmac_send_config_cmd(fmac, IWL_FMAC_VIF_ID_GLOBAL,
					       IWL_FMAC_CONFIG_TRIGGER, cmd,
					       cmd_len);
		kfree(cmd);
		if (ret)
			return ret;
	}
	return ret;
}

int iwl_fmac_run_rt_fw(struct iwl_fmac *fmac)
{
	u32 uapsd_enabled = 0;
	int ret;

	lockdep_assert_held(&fmac->mutex);

	ret = iwl_trans_start_hw(fmac->trans);
	if (ret)
		goto error;

	if (iwl_fmac_has_new_tx_api(fmac)) {
		ret = iwl_fmac_run_unified_ucode(fmac, false);
		if (ret)
			goto error;
	} else {
		ret = _iwl_fmac_run_init_fw(fmac, false);
		if (ret)
			goto error;

		iwl_fw_dbg_stop_sync(&fmac->fwrt);
		iwl_trans_stop_device(fmac->trans);
		ret = iwl_trans_start_hw(fmac->trans);
		if (ret)
			goto error;

		iwl_fw_dbg_apply_point(&fmac->fwrt, IWL_FW_INI_APPLY_EARLY);

		ret = iwl_load_fw_wait_alive(fmac, IWL_UCODE_REGULAR);
		if (ret) {
			IWL_ERR(fmac, "Failed to start RT firmware: %d\n", ret);
			goto error;
		}
		iwl_fw_dbg_apply_point(&fmac->fwrt,
				       IWL_FW_INI_APPLY_AFTER_ALIVE);

		ret = iwl_send_phy_db_data(fmac->phy_db);
		if (ret)
			goto error;

		ret = iwl_fmac_send_phy_cfg_cmd(fmac);
		if (ret)
			goto error;

	}

	iwl_get_shared_mem_conf(&fmac->fwrt);

	/* sf_update */

	/* Configure WRT, if needed */
	iwl_fw_start_dbg_conf(&fmac->fwrt, FW_DBG_START_FROM_ALIVE);
	iwl_fmac_init_triggers(fmac);

	ret = iwl_fmac_send_nvm_cmd(fmac);
	if (ret)
		goto error;

	ret = iwl_send_rss_cfg_cmd(fmac);
	if (ret)
		goto error;

	ret = iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
				       IWL_FMAC_STATIC_CONFIG_POWER_SCHEME,
				       iwlfmac_mod_params.power_scheme);
	if (ret)
		goto error;

	ret = iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
				       IWL_FMAC_STATIC_CONFIG_LTR_MODE,
				       fmac->trans->ltr_enabled);
	if (ret)
		goto error;

	if (!(iwlwifi_mod_params.uapsd_disable  & IWL_DISABLE_UAPSD_BSS))
		uapsd_enabled |= FMAC_UAPSD_ENABLE_BSS;
	if (!(iwlwifi_mod_params.uapsd_disable  & IWL_DISABLE_UAPSD_P2P_CLIENT))
		uapsd_enabled |= FMAC_UAPSD_ENABLE_P2P_CLIENT;

	ret = iwl_fmac_send_config_u32(fmac, IWL_FMAC_VIF_ID_GLOBAL,
				       IWL_FMAC_STATIC_CONFIG_UAPSD_ENABLED,
				       uapsd_enabled);
	if (ret)
		goto error;

	ret = iwl_fmac_send_config_cmd(fmac, IWL_FMAC_VIF_ID_GLOBAL,
				       IWL_FMAC_STATIC_CONFIG_COMPLETE,
				       NULL, 0);
	if (ret)
		goto error;

	ret = iwl_fmac_config_regulatory(fmac);
	if (ret)
		goto error;

	return 0;

error:
	return ret;
}

void iwl_fmac_stop_device(struct iwl_fmac *fmac)
{
	lockdep_assert_held(&fmac->mutex);
	iwl_fw_cancel_timestamp(&fmac->fwrt);
	iwl_fw_dbg_stop_sync(&fmac->fwrt);
	iwl_trans_stop_device(fmac->trans);
	iwl_free_fw_paging(&fmac->fwrt);
}

/*
 * Will return 0 even if the cmd failed when RFKILL is asserted unless
 * CMD_WANT_SKB is set in cmd->flags.
 */
int iwl_fmac_send_cmd(struct iwl_fmac *fmac, struct iwl_host_cmd *cmd)
{
	int ret;

	/* TODO: D0i3 */

	/*
	 * Synchronous commands from this op-mode must hold
	 * the mutex, this ensures we don't try to send two
	 * (or more) synchronous commands at a time.
	 */
	if (!(cmd->flags & CMD_ASYNC))
		lockdep_assert_held(&fmac->mutex);

	ret = iwl_trans_send_cmd(fmac->trans, cmd);

	/*
	 * If the caller wants the SKB, then don't hide any problems, the
	 * caller might access the response buffer which will be NULL if
	 * the command failed.
	 */
	if (cmd->flags & CMD_WANT_SKB)
		return ret;

	/* Silently ignore failures if RFKILL is asserted */
	if (!ret || ret == -ERFKILL)
		return 0;
	return ret;
}

int iwl_fmac_send_cmd_pdu(struct iwl_fmac *fmac, u32 id,
			  u32 flags, u16 len, const void *data)
{
	struct iwl_host_cmd cmd = {
		.id = id,
		.len = { len, },
		.data = { data, },
		.flags = flags,
	};

	return iwl_fmac_send_cmd(fmac, &cmd);
}

/* We assume that the caller set the status to the success value */
int iwl_fmac_send_cmd_status(struct iwl_fmac *fmac, struct iwl_host_cmd *cmd,
			     u32 *status)
{
	struct iwl_rx_packet *pkt;
	struct iwl_cmd_response *resp;
	int ret, resp_len;

	lockdep_assert_held(&fmac->mutex);

	/*
	 * Only synchronous commands can wait for status,
	 * we use WANT_SKB so the caller can't.
	 */
	if (WARN_ONCE(cmd->flags & (CMD_ASYNC | CMD_WANT_SKB),
		      "cmd flags %x", cmd->flags))
		return -EINVAL;

	cmd->flags |= CMD_WANT_SKB;

	ret = iwl_trans_send_cmd(fmac->trans, cmd);
	if (ret == -ERFKILL) {
		/*
		 * The command failed because of RFKILL, don't update
		 * the status, leave it as success and return 0.
		 */
		return 0;
	} else if (ret) {
		return ret;
	}

	pkt = cmd->resp_pkt;

	resp_len = iwl_rx_packet_payload_len(pkt);
	if (WARN_ON_ONCE(resp_len != sizeof(*resp))) {
		ret = -EIO;
		goto out_free_resp;
	}

	resp = (void *)pkt->data;
	*status = le32_to_cpu(resp->status);
 out_free_resp:
	iwl_free_resp(cmd);
	return ret;
}

/* We assume that the caller set the status to the success value */
int iwl_fmac_send_cmd_pdu_status(struct iwl_fmac *fmac, u32 id, u16 len,
				 const void *data, u32 *status)
{
	struct iwl_host_cmd cmd = {
		.id = id,
		.len = { len, },
		.data = { data, },
	};

	return iwl_fmac_send_cmd_status(fmac, &cmd, status);
}

static const struct {
	const char *name;
	u8 num;
} advanced_lookup[] = {
	{ "NMI_INTERRUPT_WDG", 0x34 },
	{ "SYSASSERT", 0x35 },
	{ "UCODE_VERSION_MISMATCH", 0x37 },
	{ "BAD_COMMAND", 0x38 },
	{ "BAD_COMMAND", 0x39 },
	{ "NMI_INTERRUPT_DATA_ACTION_PT", 0x3C },
	{ "FATAL_ERROR", 0x3D },
	{ "NMI_TRM_HW_ERR", 0x46 },
	{ "NMI_INTERRUPT_TRM", 0x4C },
	{ "NMI_INTERRUPT_BREAK_POINT", 0x54 },
	{ "NMI_INTERRUPT_WDG_RXF_FULL", 0x5C },
	{ "NMI_INTERRUPT_WDG_NO_RBD_RXF_FULL", 0x64 },
	{ "NMI_INTERRUPT_HOST", 0x66 },
	{ "NMI_INTERRUPT_ACTION_PT", 0x7C },
	{ "NMI_INTERRUPT_UNKNOWN", 0x84 },
	{ "NMI_INTERRUPT_INST_ACTION_PT", 0x86 },
	{ "ADVANCED_SYSASSERT", 0 },
};

static const char *desc_lookup(u32 num)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(advanced_lookup) - 1; i++)
		if (advanced_lookup[i].num == num)
			return advanced_lookup[i].name;

	/* No entry matches 'num', so it is the last: ADVANCED_SYSASSERT */
	return advanced_lookup[i].name;
}

struct iwl_error_event_table {
	u32 valid;		/* (nonzero) valid, (0) log is empty */
	u32 error_id;		/* type of error */
	u32 trm_hw_status0;	/* TRM HW status */
	u32 trm_hw_status1;	/* TRM HW status */
	u32 blink2;		/* branch link */
	u32 ilink1;		/* interrupt link */
	u32 ilink2;		/* interrupt link */
	u32 data1;		/* error-specific data */
	u32 data2;		/* error-specific data */
	u32 data3;		/* error-specific data */
	u32 bcon_time;		/* beacon timer */
	u32 tsf_low;		/* network timestamp function timer */
	u32 tsf_hi;		/* network timestamp function timer */
	u32 gp1;		/* GP1 timer register */
	u32 gp2;		/* GP2 timer register */
	u32 fw_rev_type;	/* firmware revision type */
	u32 major;		/* uCode version major */
	u32 minor;		/* uCode version minor */
	u32 hw_ver;		/* HW Silicon version */
	u32 brd_ver;		/* HW board version */
	u32 log_pc;		/* log program counter */
	u32 frame_ptr;		/* frame pointer */
	u32 stack_ptr;		/* stack pointer */
	u32 hcmd;		/* last host command header */
	u32 isr0;		/* isr status register LMPM_NIC_ISR0:
				 * rxtx_flag */
	u32 isr1;		/* isr status register LMPM_NIC_ISR1:
				 * host_flag */
	u32 isr2;		/* isr status register LMPM_NIC_ISR2:
				 * enc_flag */
	u32 isr3;		/* isr status register LMPM_NIC_ISR3:
				 * time_flag */
	u32 isr4;		/* isr status register LMPM_NIC_ISR4:
				 * wico interrupt */
	u32 last_cmd_id;	/* last HCMD id handled by the firmware */
	u32 wait_event;		/* wait event() caller address */
	u32 l2p_control;	/* L2pControlField */
	u32 l2p_duration;	/* L2pDurationField */
	u32 l2p_mhvalid;	/* L2pMhValidBits */
	u32 l2p_addr_match;	/* L2pAddrMatchStat */
	u32 lmpm_pmg_sel;	/* indicate which clocks are turned on
				 * (LMPM_PMG_SEL) */
	u32 u_timestamp;	/* indicate when the date and time of the
				 * compilation */
	u32 flow_handler;	/* FH read/write pointers, RX credit */
} __packed /* LOG_ERROR_TABLE_API_S_VER_3 */;

/*
 * UMAC error struct - relevant starting from family 8000 chip.
 * Note: This structure is read from the device with IO accesses,
 * and the reading already does the endian conversion. As it is
 * read with u32-sized accesses, any members with a different size
 * need to be ordered correctly though!
 */
struct iwl_umac_error_event_table {
	u32 valid;		/* (nonzero) valid, (0) log is empty */
	u32 error_id;		/* type of error */
	u32 blink1;		/* branch link */
	u32 blink2;		/* branch link */
	u32 ilink1;		/* interrupt link */
	u32 ilink2;		/* interrupt link */
	u32 data1;		/* error-specific data */
	u32 data2;		/* error-specific data */
	u32 data3;		/* error-specific data */
	u32 umac_major;
	u32 umac_minor;
	u32 frame_pointer;	/* core register 27*/
	u32 stack_pointer;	/* core register 28 */
	u32 cmd_header;		/* latest host cmd sent to UMAC */
	u32 nic_isr_pref;	/* ISR status register */
} __packed;

static void iwl_fmac_dump_umac_error_log(struct iwl_fmac *fmac)
{
	struct iwl_trans *trans = fmac->trans;
	struct iwl_umac_error_event_table table;
	u32 base = fmac->trans->dbg.umac_error_event_table;

	if (base < trans->cfg->min_umac_error_event_table) {
		IWL_ERR(fmac,
			"Not valid error log pointer 0x%08X for %s uCode\n",
			base,
			(fmac->fwrt.cur_fw_img == IWL_UCODE_INIT) ?
				"Init" : "RT");
		return;
	}

	iwl_trans_read_mem_bytes(trans, base, &table, sizeof(table));

	if (table.valid)
		fmac->fwrt.dump.umac_err_id = table.error_id;

	IWL_ERR(fmac, "0x%08X | %s\n", table.error_id,
		desc_lookup(table.error_id));
	IWL_ERR(fmac, "0x%08X | umac branchlink1\n", table.blink1);
	IWL_ERR(fmac, "0x%08X | umac branchlink2\n", table.blink2);
	IWL_ERR(fmac, "0x%08X | umac interruptlink1\n", table.ilink1);
	IWL_ERR(fmac, "0x%08X | umac interruptlink2\n", table.ilink2);
	IWL_ERR(fmac, "0x%08X | umac data1\n", table.data1);
	IWL_ERR(fmac, "0x%08X | umac data2\n", table.data2);
	IWL_ERR(fmac, "0x%08X | umac data3\n", table.data3);
	IWL_ERR(fmac, "0x%08X | umac major\n", table.umac_major);
	IWL_ERR(fmac, "0x%08X | umac minor\n", table.umac_minor);
	IWL_ERR(fmac, "0x%08X | frame pointer\n", table.frame_pointer);
	IWL_ERR(fmac, "0x%08X | stack pointer\n", table.stack_pointer);
	IWL_ERR(fmac, "0x%08X | last host cmd\n", table.cmd_header);
	IWL_ERR(fmac, "0x%08X | isr status reg\n", table.nic_isr_pref);
}

static void iwl_fmac_dump_lmac_error_log(struct iwl_fmac *fmac, u8 lmac_num)
{
	struct iwl_trans *trans = fmac->trans;
	struct iwl_error_event_table table;
	u32 base = fmac->trans->dbg.lmac_error_event_table[lmac_num];

	if (base < 0x400000) {
		IWL_ERR(fmac,
			"Not valid error log pointer 0x%08X for %s uCode\n",
			base,
			(fmac->fwrt.cur_fw_img == IWL_UCODE_INIT) ?
				"Init" : "RT");
		return;
	}

	iwl_trans_read_mem_bytes(trans, base, &table, sizeof(table));

	if (table.valid)
		fmac->fwrt.dump.lmac_err_id[lmac_num] = table.error_id;

	/* Do not change this output - scripts rely on it */

	IWL_ERR(fmac, "Loaded firmware version: %s\n", fmac->fw->fw_version);

	IWL_ERR(fmac, "0x%08X | %-28s\n", table.error_id,
		desc_lookup(table.error_id));
	IWL_ERR(fmac, "0x%08X | trm_hw_status0\n", table.trm_hw_status0);
	IWL_ERR(fmac, "0x%08X | trm_hw_status1\n", table.trm_hw_status1);
	IWL_ERR(fmac, "0x%08X | branchlink2\n", table.blink2);
	IWL_ERR(fmac, "0x%08X | interruptlink1\n", table.ilink1);
	IWL_ERR(fmac, "0x%08X | interruptlink2\n", table.ilink2);
	IWL_ERR(fmac, "0x%08X | data1\n", table.data1);
	IWL_ERR(fmac, "0x%08X | data2\n", table.data2);
	IWL_ERR(fmac, "0x%08X | data3\n", table.data3);
	IWL_ERR(fmac, "0x%08X | beacon time\n", table.bcon_time);
	IWL_ERR(fmac, "0x%08X | tsf low\n", table.tsf_low);
	IWL_ERR(fmac, "0x%08X | tsf hi\n", table.tsf_hi);
	IWL_ERR(fmac, "0x%08X | time gp1\n", table.gp1);
	IWL_ERR(fmac, "0x%08X | time gp2\n", table.gp2);
	IWL_ERR(fmac, "0x%08X | uCode revision type\n", table.fw_rev_type);
	IWL_ERR(fmac, "0x%08X | uCode version major\n", table.major);
	IWL_ERR(fmac, "0x%08X | uCode version minor\n", table.minor);
	IWL_ERR(fmac, "0x%08X | hw version\n", table.hw_ver);
	IWL_ERR(fmac, "0x%08X | board version\n", table.brd_ver);
	IWL_ERR(fmac, "0x%08X | hcmd\n", table.hcmd);
	IWL_ERR(fmac, "0x%08X | isr0\n", table.isr0);
	IWL_ERR(fmac, "0x%08X | isr1\n", table.isr1);
	IWL_ERR(fmac, "0x%08X | isr2\n", table.isr2);
	IWL_ERR(fmac, "0x%08X | isr3\n", table.isr3);
	IWL_ERR(fmac, "0x%08X | isr4\n", table.isr4);
	IWL_ERR(fmac, "0x%08X | last cmd Id\n", table.last_cmd_id);
	IWL_ERR(fmac, "0x%08X | wait_event\n", table.wait_event);
	IWL_ERR(fmac, "0x%08X | l2p_control\n", table.l2p_control);
	IWL_ERR(fmac, "0x%08X | l2p_duration\n", table.l2p_duration);
	IWL_ERR(fmac, "0x%08X | l2p_mhvalid\n", table.l2p_mhvalid);
	IWL_ERR(fmac, "0x%08X | l2p_addr_match\n", table.l2p_addr_match);
	IWL_ERR(fmac, "0x%08X | lmpm_pmg_sel\n", table.lmpm_pmg_sel);
	IWL_ERR(fmac, "0x%08X | timestamp\n", table.u_timestamp);
	IWL_ERR(fmac, "0x%08X | flow_handler\n", table.flow_handler);
}


void iwl_fmac_dump_nic_error_log(struct iwl_fmac *fmac)
{
	iwl_fmac_dump_lmac_error_log(fmac, 0);
	if (fmac->trans->dbg.lmac_error_event_table[1])
		iwl_fmac_dump_lmac_error_log(fmac, 1);
	iwl_fmac_dump_umac_error_log(fmac);
	iwl_fw_error_print_fseq_regs(&fmac->fwrt);
}

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */
#include <net/cfg80211.h>
#include <linux/etherdevice.h>
#include "mld.h"
#include "constants.h"
#include "sta.h"
#include "phy.h"
#include "iface.h"
#include "ftm-responder.h"

struct iwl_mld_pasn_sta {
	struct list_head list;
	struct iwl_mld_int_sta int_sta;
	u8 addr[ETH_ALEN];

	/* must be last as it is followed by buffer holding the key */
	struct ieee80211_key_conf keyconf;
};

struct iwl_mld_pasn_hltk_data {
	u8 *addr;
	u8 cipher;
	u8 *hltk;
};

static void
iwl_mld_ftm_responder_set_ndp(struct iwl_mld *mld,
			      struct iwl_tof_responder_config_cmd *cmd)
{
	/* Up to 2 R2I STS are allowed on the responder */
	u32 r2i_max_sts = IWL_MLD_FTM_R2I_MAX_STS < 2 ?
		IWL_MLD_FTM_R2I_MAX_STS : 1;

	cmd->r2i_ndp_params = IWL_MLD_FTM_R2I_MAX_REP |
		(r2i_max_sts << IWL_RESPONDER_STS_POS) |
		(IWL_MLD_FTM_R2I_MAX_TOTAL_LTF << IWL_RESPONDER_TOTAL_LTF_POS);
	cmd->i2r_ndp_params = IWL_MLD_FTM_I2R_MAX_REP |
		(IWL_MLD_FTM_I2R_MAX_STS << IWL_RESPONDER_STS_POS) |
		(IWL_MLD_FTM_I2R_MAX_TOTAL_LTF << IWL_RESPONDER_TOTAL_LTF_POS);
	cmd->cmd_valid_fields |=
		cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_NDP_PARAMS);
}

static int iwl_mld_ftm_responder_set_bw(struct iwl_mld *mld,
					struct cfg80211_chan_def *chandef,
					u8 *format_bw, u8 *ctrl_ch_position)
{
	switch (chandef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_LEGACY;
		*format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_20:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
		*format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_40:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
		*format_bw |= IWL_LOCATION_BW_40MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	case NL80211_CHAN_WIDTH_80:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_VHT;
		*format_bw |= IWL_LOCATION_BW_80MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	case NL80211_CHAN_WIDTH_160:
		*format_bw = IWL_LOCATION_FRAME_FORMAT_HE;
		*format_bw |= IWL_LOCATION_BW_160MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	case NL80211_CHAN_WIDTH_320:
		if (!fw_has_capa(&mld->fw->ucode_capa,
				 IWL_UCODE_TLV_CAPA_TOF_320MHZ_SUPPORT)) {
			IWL_ERR(mld, "No support for 320MHz measurement\n");
			return -EOPNOTSUPP;
		}

		*format_bw = IWL_LOCATION_FRAME_FORMAT_HE;
		*format_bw |= IWL_LOCATION_BW_320MHZ << LOCATION_BW_POS;
		*ctrl_ch_position = iwl_mld_get_fw_ctrl_pos(chandef);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
iwl_mld_ftm_responder_cmd(struct iwl_mld *mld,
			  struct ieee80211_vif *vif,
			  struct cfg80211_chan_def *chandef,
			  struct ieee80211_bss_conf *link_conf)
{
	u32 cmd_id = WIDE_ID(LOCATION_GROUP, TOF_RESPONDER_CONFIG_CMD);
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct iwl_tof_responder_config_cmd cmd = {
		.channel_num = chandef->chan->hw_value,
		.cmd_valid_fields =
			cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_CHAN_INFO |
				    IWL_TOF_RESPONDER_CMD_VALID_BSSID |
				    IWL_TOF_RESPONDER_CMD_VALID_STA_ID),
	};
	int err;
	struct iwl_mld_link *mld_link;

	lockdep_assert_wiphy(mld->wiphy);

	mld_link = iwl_mld_link_dereference_check(mld_vif, link_conf->link_id);
	if (WARN_ON(!mld_link || mld_link->bcast_sta.sta_id == IWL_INVALID_STA))
		return -EINVAL;

	cmd.sta_id = mld_link->bcast_sta.sta_id;
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	cmd.cmd_valid_fields |=
		cpu_to_le32(mld->trans->dbg_cfg.MLD_FTM_RESP_VALID);
	cmd.responder_cfg_flags |=
		cpu_to_le32(mld->trans->dbg_cfg.MLD_FTM_RESP_FLAGS);

	if (mld->trans->dbg_cfg.MLD_FTM_RESP_TOA_OFFSET) {
		cmd.cmd_valid_fields |=
			cpu_to_le32(IWL_TOF_RESPONDER_FLAGS_TOA_OFFSET_MODE);
		cmd.toa_offset =
			cpu_to_le16(mld->trans->dbg_cfg.MLD_FTM_RESP_TOA_OFFSET);
	}
#endif

	cmd.band = iwl_mld_nl80211_band_to_fw(chandef->chan->band);

	/* Use a default of bss_color=1 for now */
	cmd.cmd_valid_fields |=
		cpu_to_le32(IWL_TOF_RESPONDER_CMD_VALID_BSS_COLOR |
			    IWL_TOF_RESPONDER_CMD_VALID_MIN_MAX_TIME_BETWEEN_MSR);
	cmd.bss_color = 1;
	cmd.min_time_between_msr =
		cpu_to_le16(IWL_MLD_FTM_NON_TB_MIN_TIME_BETWEEN_MSR);
	cmd.max_time_between_msr =
		cpu_to_le16(IWL_MLD_FTM_NON_TB_MAX_TIME_BETWEEN_MSR);

	iwl_mld_ftm_responder_set_ndp(mld, &cmd);

	err = iwl_mld_ftm_responder_set_bw(mld, chandef, &cmd.format_bw,
					   &cmd.ctrl_ch_position);

	if (err) {
		IWL_ERR(mld, "Failed to set responder bandwidth\n");
		return err;
	}

	memcpy(cmd.bssid, vif->addr, ETH_ALEN);

	return iwl_mld_send_cmd_pdu(mld, cmd_id, &cmd);
}

static int
iwl_mld_ftm_responder_dyn_cfg_cmd(struct iwl_mld *mld,
				  struct ieee80211_ftm_responder_params *params,
				  struct iwl_mld_pasn_hltk_data *hltk_data)
{
	struct iwl_tof_responder_dyn_config_cmd cmd;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(LOCATION_GROUP, TOF_RESPONDER_DYN_CONFIG_CMD),
		.data[0] = &cmd,
		.len[0] = sizeof(cmd),
		/* may not be able to DMA from stack */
		.dataflags[0] = IWL_HCMD_DFL_DUP,
	};

	lockdep_assert_wiphy(mld->wiphy);

	cmd.valid_flags = 0;

	if (params) {
		if (params->lci_len + 2 > sizeof(cmd.lci_buf) ||
		    params->civicloc_len + 2 > sizeof(cmd.civic_buf)) {
			IWL_ERR(mld,
				"LCI/civic data too big (lci=%zd, civic=%zd)\n",
				params->lci_len, params->civicloc_len);
			return -ENOBUFS;
		}

		if (params->lci_len) {
			cmd.lci_buf[0] = WLAN_EID_MEASURE_REPORT;
			cmd.lci_buf[1] = params->lci_len;
			memcpy(cmd.lci_buf + 2, params->lci, params->lci_len);
			cmd.lci_len = params->lci_len + 2;
			cmd.valid_flags |= IWL_RESPONDER_DYN_CFG_VALID_LCI;
		}

		if (params->civicloc_len) {
			cmd.civic_buf[0] = WLAN_EID_MEASURE_REPORT;
			cmd.civic_buf[1] = params->civicloc_len;
			memcpy(cmd.civic_buf + 2, params->civicloc,
			       params->civicloc_len);
			cmd.civic_len = params->civicloc_len + 2;
			cmd.valid_flags |= IWL_RESPONDER_DYN_CFG_VALID_CIVIC;
		}
	}

	if (hltk_data) {
		if (hltk_data->cipher > IWL_LOCATION_CIPHER_GCMP_256) {
			IWL_ERR(mld, "invalid cipher: %u\n",
				hltk_data->cipher);
			return -EINVAL;
		}

		cmd.cipher = hltk_data->cipher;
		memcpy(cmd.addr, hltk_data->addr, sizeof(cmd.addr));

		BUILD_BUG_ON(sizeof(cmd.hltk_buf) != HLTK_11AZ_LEN);
		memcpy(cmd.hltk_buf, hltk_data->hltk, sizeof(cmd.hltk_buf));
		cmd.valid_flags |= IWL_RESPONDER_DYN_CFG_VALID_PASN_STA;
	}

	return iwl_mld_send_cmd(mld, &hcmd);
}

int iwl_mld_ftm_start_responder(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct ieee80211_bss_conf *bss_conf)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	struct ieee80211_chanctx_conf *ctx;
	struct cfg80211_chan_def *chandef;
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (WARN_ON_ONCE(!bss_conf->ftm_responder))
		return -EINVAL;

	if (vif->p2p || vif->type != NL80211_IFTYPE_AP ||
	    !mld_vif->ap_ibss_active) {
		IWL_ERR(mld, "Cannot start responder, not in AP mode\n");
		return -EIO;
	}

	ctx = wiphy_dereference(mld->wiphy, bss_conf->chanctx_conf);
	chandef = iwl_mld_get_chandef_from_chanctx(mld, ctx);

	ret = iwl_mld_ftm_responder_cmd(mld, vif, chandef, bss_conf);
	if (ret)
		return ret;

	if (bss_conf->ftmr_params)
		ret = iwl_mld_ftm_responder_dyn_cfg_cmd(mld,
							bss_conf->ftmr_params,
							NULL);

	return ret;
}

static void iwl_mld_resp_del_pasn_sta(struct iwl_mld *mld,
				      struct ieee80211_vif *vif,
				      struct iwl_mld_pasn_sta *sta)
{
	list_del(&sta->list);

	iwl_mld_remove_pasn_sta(mld, vif, &sta->int_sta, &sta->keyconf);

	kfree(sta);
}

int iwl_mld_ftm_resp_remove_pasn_sta(struct iwl_mld *mld,
				     struct ieee80211_vif *vif, u8 *addr)
{
	struct iwl_mld_pasn_sta *sta, *prev;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry_safe(sta, prev, &mld->ftm_responder.resp_pasn_list,
				 list) {
		if (!memcmp(sta->addr, addr, ETH_ALEN)) {
			iwl_mld_resp_del_pasn_sta(mld, vif, sta);
			return 0;
		}
	}

	IWL_ERR(mld, "FTM: PASN station %pM not found\n", addr);
	return -EINVAL;
}

int iwl_mld_ftm_responder_add_pasn_sta(struct iwl_mld *mld,
				       struct ieee80211_vif *vif,
				       u8 *addr, u32 cipher, u8 *tk, u32 tk_len,
				       u8 *hltk, u32 hltk_len)
{
	int ret;
	struct iwl_mld_pasn_sta *sta = NULL;

	lockdep_assert_wiphy(mld->wiphy);

	if ((!hltk || !hltk_len) && (!tk || !tk_len)) {
		IWL_ERR(mld, "TK and HLTK not set\n");
		return -EINVAL;
	}

	if (hltk && hltk_len) {
		struct iwl_mld_pasn_hltk_data hltk_data = {
			.addr = addr,
			.hltk = hltk,
		};

		if (!fw_has_capa(&mld->fw->ucode_capa,
				 IWL_UCODE_TLV_CAPA_SECURE_LTF_SUPPORT)) {
			IWL_ERR(mld, "No support for secure LTF measurement\n");
			return -EINVAL;
		}

		hltk_data.cipher = iwl_mld_cipher_to_location_cipher(cipher);
		if (hltk_data.cipher == IWL_LOCATION_CIPHER_INVALID) {
			IWL_ERR(mld, "invalid cipher: %u\n", cipher);
			return -EINVAL;
		}

		ret = iwl_mld_ftm_responder_dyn_cfg_cmd(mld, NULL, &hltk_data);
		if (ret)
			return ret;
	}

	if (tk && tk_len) {
		sta = kzalloc(sizeof(*sta) + tk_len, GFP_KERNEL);
		if (!sta)
			return -ENOBUFS;

		ret = iwl_mld_add_pasn_sta(mld, vif, &sta->int_sta, addr,
					   cipher, tk, tk_len, &sta->keyconf);
		if (ret) {
			kfree(sta);
			return ret;
		}

		memcpy(sta->addr, addr, ETH_ALEN);
		list_add_tail(&sta->list, &mld->ftm_responder.resp_pasn_list);
	}

	return ret;
}

void iwl_mld_ftm_responder_clear(struct iwl_mld *mld, struct ieee80211_vif *vif)
{
	struct iwl_mld_pasn_sta *sta, *prev;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry_safe(sta, prev, &mld->ftm_responder.resp_pasn_list,
				 list)
		iwl_mld_resp_del_pasn_sta(mld, vif, sta);
}

void iwl_mld_ftm_responder_init(struct iwl_mld *mld)
{
	INIT_LIST_HEAD(&mld->ftm_responder.resp_pasn_list);
}

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025-2026 Intel Corporation
 */
#include <linux/etherdevice.h>
#include <linux/math64.h>
#include <net/cfg80211.h>
#include "mld.h"
#include "iface.h"
#include "phy.h"
#include "iwl-io.h"
#include "iwl-prph.h"
#include "constants.h"
#include "fw/api/location.h"
#include "ftm-initiator.h"

enum iwl_mld_pasn_flags {
	IWL_MLD_PASN_FLAG_HAS_HLTK = BIT(0),
};

struct iwl_mld_ftm_pasn_entry {
	struct list_head list;
	u8 addr[ETH_ALEN];
	u8 hltk[HLTK_11AZ_LEN];
	u8 tk[TK_11AZ_LEN];
	u8 cipher;
	u8 tx_pn[IEEE80211_CCMP_PN_LEN];
	u8 rx_pn[IEEE80211_CCMP_PN_LEN];
	u32 flags;
};

struct iwl_mld_lci_civic_entry {
	struct list_head list;
	u8 addr[ETH_ALEN];
	u8 lci_len, civic_len;
	u8 buf[];
};

static void iwl_mld_ftm_cmd_common(struct iwl_mld *mld,
				   struct ieee80211_vif *vif,
				   struct iwl_tof_range_req_cmd *cmd,
				   struct cfg80211_pmsr_request *req)
{
	int i;

	cmd->initiator_flags =
		cpu_to_le32(IWL_TOF_INITIATOR_FLAGS_MACADDR_RANDOM |
			    IWL_TOF_INITIATOR_FLAGS_NON_ASAP_SUPPORT);
	cmd->request_id = req->cookie;
	cmd->num_of_ap = req->n_peers;

	/* Use a large value for "no timeout". Don't use the maximum value
	 * because of fw limitations.
	 */
	if (req->timeout)
		cmd->req_timeout_ms = cpu_to_le32(min(req->timeout, 0xfffff));
	else
		cmd->req_timeout_ms = cpu_to_le32(0xfffff);

	memcpy(cmd->macaddr_template, req->mac_addr, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++)
		cmd->macaddr_mask[i] = ~req->mac_addr_mask[i];

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (IWL_MLD_FTM_INITIATOR_FAST_ALGO_DISABLE)
		cmd->initiator_flags |=
			cpu_to_le32(IWL_TOF_INITIATOR_FLAGS_FAST_ALGO_DISABLED);
#endif

	if (vif->cfg.assoc) {
		memcpy(cmd->range_req_bssid, vif->bss_conf.bssid, ETH_ALEN);

		/* AP's TSF is only relevant if associated */
		for (i = 0; i < req->n_peers; i++) {
			if (req->peers[i].report_ap_tsf) {
				struct iwl_mld_vif *mld_vif =
					iwl_mld_vif_from_mac80211(vif);

				cmd->tsf_mac_id = cpu_to_le32(mld_vif->fw_id);
				return;
			}
		}
	} else {
		eth_broadcast_addr(cmd->range_req_bssid);
	}

	/* Don't report AP's TSF */
	cmd->tsf_mac_id = cpu_to_le32(0xff);
}

static int
iwl_mld_ftm_set_target_chandef(struct iwl_mld *mld,
			       struct cfg80211_pmsr_request_peer *peer,
			       struct iwl_tof_range_req_ap_entry *target)
{
	u32 freq = peer->chandef.chan->center_freq;

	target->channel_num = ieee80211_frequency_to_channel(freq);

	switch (peer->chandef.width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		target->format_bw = IWL_LOCATION_FRAME_FORMAT_LEGACY;
		target->format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_20:
		target->format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
		target->format_bw |= IWL_LOCATION_BW_20MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_40:
		target->format_bw = IWL_LOCATION_FRAME_FORMAT_HT;
		target->format_bw |= IWL_LOCATION_BW_40MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_80:
		target->format_bw = IWL_LOCATION_FRAME_FORMAT_VHT;
		target->format_bw |= IWL_LOCATION_BW_80MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_160:
		target->format_bw = IWL_LOCATION_FRAME_FORMAT_HE;
		target->format_bw |= IWL_LOCATION_BW_160MHZ << LOCATION_BW_POS;
		break;
	case NL80211_CHAN_WIDTH_320:
		if (!fw_has_capa(&mld->fw->ucode_capa,
				 IWL_UCODE_TLV_CAPA_TOF_320MHZ_SUPPORT)) {
			IWL_ERR(mld,
				"No support for 320MHz measurement\n");
			return -EOPNOTSUPP;
		}

		target->format_bw = IWL_LOCATION_FRAME_FORMAT_HE;
		target->format_bw |= IWL_LOCATION_BW_320MHZ << LOCATION_BW_POS;
		break;
	default:
		IWL_ERR(mld, "Unsupported BW in FTM request (%d)\n",
			peer->chandef.width);
		return -EINVAL;
	}

	/* non EDCA based measurement must use HE preamble */
	if (peer->ftm.trigger_based || peer->ftm.non_trigger_based)
		target->format_bw |= IWL_LOCATION_FRAME_FORMAT_HE;

	target->ctrl_ch_position =
		(peer->chandef.width > NL80211_CHAN_WIDTH_20) ?
		iwl_mld_get_fw_ctrl_pos(&peer->chandef) : 0;

	target->band = iwl_mld_nl80211_band_to_fw(peer->chandef.chan->band);
	return 0;
}

#define FTM_SET_FLAG(flag) (target->initiator_ap_flags |= \
			    cpu_to_le32(IWL_INITIATOR_AP_FLAGS_##flag))

static void
iwl_mld_ftm_set_target_flags(struct iwl_mld *mld,
			     struct cfg80211_pmsr_request_peer *peer,
			     struct iwl_tof_range_req_ap_entry *target)
{
	target->initiator_ap_flags = cpu_to_le32(0);

	if (peer->ftm.asap)
		FTM_SET_FLAG(ASAP);

	if (peer->ftm.request_lci)
		FTM_SET_FLAG(LCI_REQUEST);

	if (peer->ftm.request_civicloc)
		FTM_SET_FLAG(CIVIC_REQUEST);

	if (IWL_MLD_FTM_INITIATOR_DYNACK)
		FTM_SET_FLAG(DYN_ACK);

	if (IWL_MLD_FTM_INITIATOR_ALGO == IWL_TOF_ALGO_TYPE_LINEAR_REG)
		FTM_SET_FLAG(ALGO_LR);
	else if (IWL_MLD_FTM_INITIATOR_ALGO == IWL_TOF_ALGO_TYPE_FFT)
		FTM_SET_FLAG(ALGO_FFT);

	if (peer->ftm.trigger_based)
		FTM_SET_FLAG(TB);
	else if (peer->ftm.non_trigger_based)
		FTM_SET_FLAG(NON_TB);

	if ((peer->ftm.trigger_based || peer->ftm.non_trigger_based) &&
	    peer->ftm.lmr_feedback)
		FTM_SET_FLAG(LMR_FEEDBACK);

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (IWL_MLD_FTM_INITIATOR_MCSI_ENABLED)
		FTM_SET_FLAG(MCSI_REPORT);

	if (IWL_MLD_FTM_LMR_FEEDBACK_TERMINATE)
		FTM_SET_FLAG(TERMINATE_ON_LMR_FEEDBACK);

	if (IWL_MLD_FTM_TEST_INCORRECT_SAC)
		FTM_SET_FLAG(TEST_INCORRECT_SAC);

	if (IWL_MLD_FTM_TEST_BAD_SLTF)
		FTM_SET_FLAG(TEST_BAD_SLTF);
#endif
}

static void iwl_mld_ftm_set_sta(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct cfg80211_pmsr_request_peer *peer,
				struct iwl_tof_range_req_ap_entry *target)
{
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);
	u32 sta_id_mask;

	target->sta_id = IWL_INVALID_STA;

#ifdef CPTCFG_IWLWIFI_DEBUGFS
	if (mld_vif->ftm_unprotected)
		return;
#endif

	if (!vif->cfg.assoc || !mld_vif->ap_sta)
		return;

	sta_id_mask = iwl_mld_fw_sta_id_mask(mld, mld_vif->ap_sta);
	if (WARN_ON(hweight32(sta_id_mask) != 1))
		return;

	target->sta_id = __ffs(sta_id_mask);

	if (mld_vif->ap_sta->mfp &&
	    (peer->ftm.trigger_based || peer->ftm.non_trigger_based))
		FTM_SET_FLAG(PMF);
}

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
static void iwl_mld_ftm_set_calib(struct iwl_mld *mld, __le16 *calib,
				  struct iwl_tof_range_req_ap_entry *target)
{
	if (mld->trans->dbg_cfg.MLD_FTM_INITIATOR_COMMON_CALIB) {
		/* The driver API only supports one calibration value.
		 * For now, use it for all bandwidths.
		 * TODO: Add support for per bandwidth calibration
		 * values.
		 */
		for (int j = 0; j < IWL_TOF_BW_NUM; j++)
			calib[j] =
				cpu_to_le16(mld->trans->dbg_cfg.MLD_FTM_INITIATOR_COMMON_CALIB);

		FTM_SET_FLAG(USE_CALIB);
	}
}
#endif

struct iwl_mld_ftm_iter_data {
	u8 cipher;
	u8 *bssid;
	u8 *tk;
};

static void iwl_mld_ftm_set_assoc_tk_iter(struct ieee80211_hw *hw,
					  struct ieee80211_vif *vif,
					  struct ieee80211_sta *sta,
					  struct ieee80211_key_conf *key,
					  void *data)
{
	struct iwl_mld_ftm_iter_data *target = data;
	enum iwl_location_cipher cipher;

	if (!sta || memcmp(sta->addr, target->bssid, ETH_ALEN))
		return;

	if (WARN_ON(!sta->mfp))
		return;

	cipher = iwl_mld_cipher_to_location_cipher(key->cipher);
	if (WARN_ON(cipher != target->cipher))
		return;

	target->tk = key->key;
}

static u32 iwl_mld_ftm_get_tk_len(struct iwl_mld *mld, u32 cipher)
{
	switch (cipher) {
	case IWL_LOCATION_CIPHER_CCMP_128:
	case IWL_LOCATION_CIPHER_GCMP_128:
		return WLAN_KEY_LEN_CCMP;
	case IWL_LOCATION_CIPHER_GCMP_256:
		return WLAN_KEY_LEN_GCMP_256;
	default:
		IWL_ERR(mld, "Invalid cipher:%u\n", cipher);
	}

	return 0;
}

static int
iwl_mld_ftm_set_secured_ranging(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct iwl_tof_range_req_ap_entry *target)
{
	struct iwl_mld_ftm_pasn_entry *entry;
	u8 *tk;
	u32 tk_len;

#ifdef CPTCFG_IWLWIFI_DEBUGFS
	struct iwl_mld_vif *mld_vif = iwl_mld_vif_from_mac80211(vif);

	if (mld_vif->ftm_unprotected)
		return 0;
#endif

	if (!(le32_to_cpu(target->initiator_ap_flags) &
	      (IWL_INITIATOR_AP_FLAGS_NON_TB | IWL_INITIATOR_AP_FLAGS_TB)))
		return 0;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry(entry, &mld->ftm_initiator.pasn_list, list) {
		if (memcmp(entry->addr, target->bssid, sizeof(entry->addr)))
			continue;

		target->cipher = entry->cipher;

		if (entry->flags & IWL_MLD_PASN_FLAG_HAS_HLTK)
			memcpy(target->hltk, entry->hltk, sizeof(entry->hltk));
		else
			memset(target->hltk, 0, sizeof(target->hltk));

		if (vif->cfg.assoc &&
		    !memcmp(vif->bss_conf.bssid, target->bssid, ETH_ALEN)) {
			struct iwl_mld_ftm_iter_data iter_data;

			iter_data.bssid = target->bssid;
			iter_data.cipher = target->cipher;
			iter_data.tk = NULL;
			ieee80211_iter_keys(mld->hw, vif,
					    iwl_mld_ftm_set_assoc_tk_iter,
					    &iter_data);
			tk = iter_data.tk;
		} else {
			tk = entry->tk;
		}

		if (WARN_ON(!tk))
			return -EINVAL;

		tk_len = iwl_mld_ftm_get_tk_len(mld, target->cipher);
		memcpy(target->tk, tk, tk_len);

		memcpy(target->rx_pn, entry->rx_pn, sizeof(entry->rx_pn));
		memcpy(target->tx_pn, entry->tx_pn, sizeof(entry->tx_pn));

		if (IWL_MLD_FTM_INITIATOR_SECURE_LTF)
			FTM_SET_FLAG(SECURED);

		FTM_SET_FLAG(PMF);
		return 0;
	}

	return 0;
}

static int
iwl_mld_ftm_set_target(struct iwl_mld *mld, struct ieee80211_vif *vif,
		       struct cfg80211_pmsr_request_peer *peer,
		       struct iwl_tof_range_req_ap_entry *target)
{
	u32 i2r_max_sts;
	int ret;

	ret = iwl_mld_ftm_set_target_chandef(mld, peer, target);
	if (ret)
		return ret;

	memcpy(target->bssid, peer->addr, ETH_ALEN);
	target->burst_period = cpu_to_le16(peer->ftm.burst_period);
	target->samples_per_burst = peer->ftm.ftms_per_burst;
	target->num_of_bursts = peer->ftm.num_bursts_exp;
	iwl_mld_ftm_set_target_flags(mld, peer, target);
	iwl_mld_ftm_set_sta(mld, vif, peer, target);
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	iwl_mld_ftm_set_calib(mld, target->calib, target);
#endif

	ret = iwl_mld_ftm_set_secured_ranging(mld, vif, target);
	if (ret)
		return ret;

	i2r_max_sts = IWL_MLD_FTM_I2R_MAX_STS > 1 ? 1 :
		IWL_MLD_FTM_I2R_MAX_STS;

	target->r2i_ndp_params = IWL_MLD_FTM_R2I_MAX_REP |
		(IWL_MLD_FTM_R2I_MAX_STS << IWL_LOCATION_MAX_STS_POS) |
		(IWL_MLD_FTM_R2I_MAX_TOTAL_LTF << IWL_LOCATION_TOTAL_LTF_POS);
	target->i2r_ndp_params = IWL_MLD_FTM_I2R_MAX_REP |
		(i2r_max_sts << IWL_LOCATION_MAX_STS_POS) |
		(IWL_MLD_FTM_I2R_MAX_TOTAL_LTF << IWL_LOCATION_TOTAL_LTF_POS);

	if (peer->ftm.non_trigger_based) {
		target->min_time_between_msr =
			cpu_to_le16(IWL_MLD_FTM_NON_TB_MIN_TIME_BETWEEN_MSR);
		target->burst_period =
			cpu_to_le16(IWL_MLD_FTM_NON_TB_MAX_TIME_BETWEEN_MSR);
	} else {
		target->min_time_between_msr = cpu_to_le16(0);
	}

	/* TODO: Beacon interval is currently unknown, so use the common value
	 * of 100 TUs.
	 */
	target->beacon_interval = cpu_to_le16(100);

	return 0;
}

int iwl_mld_ftm_start(struct iwl_mld *mld, struct ieee80211_vif *vif,
		      struct cfg80211_pmsr_request *req)
{
	struct iwl_tof_range_req_cmd cmd;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(LOCATION_GROUP, TOF_RANGE_REQ_CMD),
		.dataflags[0] = IWL_HCMD_DFL_DUP,
		.data[0] = &cmd,
		.len[0] = sizeof(cmd),
	};
	u8 i;
	int ret;

	lockdep_assert_wiphy(mld->wiphy);

	if (mld->ftm_initiator.req)
		return -EBUSY;

	if (req->n_peers > ARRAY_SIZE(cmd.ap))
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));

	iwl_mld_ftm_cmd_common(mld, vif, (void *)&cmd, req);

	for (i = 0; i < cmd.num_of_ap; i++) {
		struct cfg80211_pmsr_request_peer *peer = &req->peers[i];
		struct iwl_tof_range_req_ap_entry *target = &cmd.ap[i];

		ret = iwl_mld_ftm_set_target(mld, vif, peer, target);
		if (ret)
			return ret;
	}

	/* TODO: get the status from the response*/
	ret = iwl_mld_send_cmd(mld, &hcmd);
	if (!ret) {
		mld->ftm_initiator.req = req;
		mld->ftm_initiator.req_wdev = ieee80211_vif_to_wdev(vif);
	}

	return ret;
}

static void iwl_mld_ftm_reset_request(struct iwl_mld *mld)
{
	struct iwl_mld_lci_civic_entry *entry, *prev;

	lockdep_assert_wiphy(mld->wiphy);

	mld->ftm_initiator.req = NULL;
	mld->ftm_initiator.req_wdev = NULL;
	memset(mld->ftm_initiator.responses, 0,
	       sizeof(mld->ftm_initiator.responses));

	list_for_each_entry_safe(entry, prev, &mld->ftm_initiator.loc_list,
				 list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void
iwl_mld_ftm_pasn_update_pn(struct iwl_mld *mld,
			   struct iwl_tof_range_rsp_ap_entry_ntfy *fw_ap)
{
	struct iwl_mld_ftm_pasn_entry *entry;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry(entry, &mld->ftm_initiator.pasn_list, list) {
		if (memcmp(fw_ap->bssid, entry->addr, sizeof(entry->addr)))
			continue;

		memcpy(entry->rx_pn, fw_ap->rx_pn, sizeof(entry->rx_pn));
		memcpy(entry->tx_pn, fw_ap->tx_pn, sizeof(entry->tx_pn));
		return;
	}
}

static int iwl_mld_ftm_range_resp_valid(struct iwl_mld *mld, u8 request_id,
					u8 num_of_aps)
{
	if (IWL_FW_CHECK(mld, request_id != (u8)mld->ftm_initiator.req->cookie,
			 "Request ID mismatch, got %u, active %u\n",
			 request_id, (u8)mld->ftm_initiator.req->cookie))
		return -EINVAL;

	if (IWL_FW_CHECK(mld, num_of_aps > mld->ftm_initiator.req->n_peers ||
			 num_of_aps > IWL_TOF_MAX_APS,
			 "FTM range response: invalid num of APs (%u)\n",
			 num_of_aps))
		return -EINVAL;

	return 0;
}

static int iwl_mld_ftm_find_peer(struct cfg80211_pmsr_request *req,
				 const u8 *addr)
{
	for (int i = 0; i < req->n_peers; i++) {
		struct cfg80211_pmsr_request_peer *peer = &req->peers[i];

		if (ether_addr_equal_unaligned(peer->addr, addr))
			return i;
	}

	return -ENOENT;
}

static void iwl_mld_ftm_get_lci_civic(struct iwl_mld *mld,
				      struct cfg80211_pmsr_result *res)
{
	struct iwl_mld_lci_civic_entry *entry;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry(entry, &mld->ftm_initiator.loc_list, list) {
		if (!ether_addr_equal_unaligned(res->addr, entry->addr))
			continue;

		if (entry->lci_len) {
			res->ftm.lci_len = entry->lci_len;
			res->ftm.lci = entry->buf;
		}

		if (entry->civic_len) {
			res->ftm.civicloc_len = entry->civic_len;
			res->ftm.civicloc = entry->buf + entry->lci_len;
		}

		break;
	}
}

static void iwl_mld_debug_range_resp(struct iwl_mld *mld, u8 index,
				     struct cfg80211_pmsr_result *res)
{
	s64 rtt_avg = div_s64(res->ftm.rtt_avg * 100, 6666);

	IWL_DEBUG_INFO(mld, "entry %d\n", index);
	IWL_DEBUG_INFO(mld, "\tstatus: %d\n", res->status);
	IWL_DEBUG_INFO(mld, "\tBSSID: %pM\n", res->addr);
	IWL_DEBUG_INFO(mld, "\thost time: %llu\n", res->host_time);
	IWL_DEBUG_INFO(mld, "\tburst index: %d\n", res->ftm.burst_index);
	IWL_DEBUG_INFO(mld, "\tsuccess num: %u\n", res->ftm.num_ftmr_successes);
	IWL_DEBUG_INFO(mld, "\trssi: %d\n", res->ftm.rssi_avg);
	IWL_DEBUG_INFO(mld, "\trssi spread: %d\n", res->ftm.rssi_spread);
	IWL_DEBUG_INFO(mld, "\trtt: %lld\n", res->ftm.rtt_avg);
	IWL_DEBUG_INFO(mld, "\trtt var: %llu\n", res->ftm.rtt_variance);
	IWL_DEBUG_INFO(mld, "\trtt spread: %llu\n", res->ftm.rtt_spread);
	IWL_DEBUG_INFO(mld, "\tdistance: %lld\n", rtt_avg);
}

void iwl_mld_handle_ftm_resp_notif(struct iwl_mld *mld,
				   struct iwl_rx_packet *pkt)
{
	struct iwl_tof_range_rsp_ntfy *fw_resp = (void *)pkt->data;
	u8 num_of_aps, last_in_batch;

	if (IWL_FW_CHECK(mld, !mld->ftm_initiator.req,
			 "FTM response without a pending request\n"))
		return;

	if (iwl_mld_ftm_range_resp_valid(mld, fw_resp->request_id,
					 fw_resp->num_of_aps))
		return;

	num_of_aps = fw_resp->num_of_aps;
	last_in_batch = fw_resp->last_report;

	IWL_DEBUG_INFO(mld, "Range response received\n");
	IWL_DEBUG_INFO(mld, "request id: %llu, num of entries: %u\n",
		       mld->ftm_initiator.req->cookie, num_of_aps);

	for (int i = 0; i < num_of_aps; i++) {
		struct cfg80211_pmsr_result result = {};
		struct iwl_tof_range_rsp_ap_entry_ntfy *fw_ap;
		int peer_idx;

		fw_ap = &fw_resp->ap[i];
		result.final = fw_ap->last_burst;
		result.ap_tsf = le32_to_cpu(fw_ap->start_tsf);
		result.ap_tsf_valid = 1;
		iwl_mld_ftm_pasn_update_pn(mld, fw_ap);

		peer_idx = iwl_mld_ftm_find_peer(mld->ftm_initiator.req,
						 fw_ap->bssid);
		if (peer_idx < 0) {
			IWL_WARN(mld,
				 "Unknown address (%pM, target #%d) in FTM response\n",
				 fw_ap->bssid, i);
			continue;
		}

		switch (fw_ap->measure_status) {
		case IWL_TOF_ENTRY_SUCCESS:
			result.status = NL80211_PMSR_STATUS_SUCCESS;
			break;
		case IWL_TOF_ENTRY_TIMING_MEASURE_TIMEOUT:
			result.status = NL80211_PMSR_STATUS_TIMEOUT;
			break;
		case IWL_TOF_ENTRY_NO_RESPONSE:
			result.status = NL80211_PMSR_STATUS_FAILURE;
			result.ftm.failure_reason =
				NL80211_PMSR_FTM_FAILURE_NO_RESPONSE;
			break;
		case IWL_TOF_ENTRY_REQUEST_REJECTED:
			result.status = NL80211_PMSR_STATUS_FAILURE;
			result.ftm.failure_reason =
				NL80211_PMSR_FTM_FAILURE_PEER_BUSY;
			result.ftm.busy_retry_time = fw_ap->refusal_period;
			break;
		default:
			result.status = NL80211_PMSR_STATUS_FAILURE;
			result.ftm.failure_reason =
				NL80211_PMSR_FTM_FAILURE_UNSPECIFIED;
			break;
		}
		memcpy(result.addr, fw_ap->bssid, ETH_ALEN);

		/* TODO: convert the timestamp from the result to systime */
		result.host_time = ktime_get_boottime_ns();

		result.type = NL80211_PMSR_TYPE_FTM;
		result.ftm.burst_index = mld->ftm_initiator.responses[peer_idx];
		mld->ftm_initiator.responses[peer_idx]++;
		result.ftm.rssi_avg = fw_ap->rssi;
		result.ftm.rssi_avg_valid = 1;
		result.ftm.rssi_spread = fw_ap->rssi_spread;
		result.ftm.rssi_spread_valid = 1;
		result.ftm.rtt_avg = (s32)le32_to_cpu(fw_ap->rtt);
		result.ftm.rtt_avg_valid = 1;
		result.ftm.rtt_variance = le32_to_cpu(fw_ap->rtt_variance);
		result.ftm.rtt_variance_valid = 1;
		result.ftm.rtt_spread = le32_to_cpu(fw_ap->rtt_spread);
		result.ftm.rtt_spread_valid = 1;

		iwl_mld_ftm_get_lci_civic(mld, &result);

		cfg80211_pmsr_report(mld->ftm_initiator.req_wdev,
				     mld->ftm_initiator.req,
				     &result, GFP_KERNEL);

		if (fw_has_api(&mld->fw->ucode_capa,
			       IWL_UCODE_TLV_API_FTM_RTT_ACCURACY))
			IWL_DEBUG_INFO(mld, "RTT confidence: %u\n",
				       fw_ap->rttConfidence);

		iwl_mld_debug_range_resp(mld, i, &result);
	}

	if (last_in_batch) {
		cfg80211_pmsr_complete(mld->ftm_initiator.req_wdev,
				       mld->ftm_initiator.req,
				       GFP_KERNEL);
		iwl_mld_ftm_reset_request(mld);
	}
}

void iwl_mld_ftm_restart_cleanup(struct iwl_mld *mld)
{
	struct cfg80211_pmsr_result result = {
		.status = NL80211_PMSR_STATUS_FAILURE,
		.final = 1,
		.host_time = ktime_get_boottime_ns(),
		.type = NL80211_PMSR_TYPE_FTM,
	};

	if (!mld->ftm_initiator.req)
		return;

	for (int i = 0; i < mld->ftm_initiator.req->n_peers; i++) {
		memcpy(result.addr, mld->ftm_initiator.req->peers[i].addr,
		       ETH_ALEN);

		cfg80211_pmsr_report(mld->ftm_initiator.req_wdev,
				     mld->ftm_initiator.req,
				     &result, GFP_KERNEL);
	}

	cfg80211_pmsr_complete(mld->ftm_initiator.req_wdev,
			       mld->ftm_initiator.req, GFP_KERNEL);
	iwl_mld_ftm_reset_request(mld);
}

void iwl_mld_ftm_remove_pasn_sta(struct iwl_mld *mld, u8 *addr)
{
	struct iwl_mld_ftm_pasn_entry *entry, *prev;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry_safe(entry, prev, &mld->ftm_initiator.pasn_list,
				 list) {
		if (memcmp(entry->addr, addr, sizeof(entry->addr)))
			continue;

		list_del(&entry->list);
		kfree(entry);
		return;
	}
}

int iwl_mld_ftm_add_pasn_sta(struct iwl_mld *mld, struct ieee80211_vif *vif,
			     u8 *addr, u32 cipher, u8 *tk, u32 tk_len,
			     u8 *hltk, u32 hltk_len)
{
	u32 expected_tk_len;
	struct iwl_mld_ftm_pasn_entry *pasn;

	lockdep_assert_wiphy(mld->wiphy);

	pasn = kzalloc(sizeof(*pasn), GFP_KERNEL);
	if (!pasn)
		return -ENOBUFS;

	iwl_mld_ftm_remove_pasn_sta(mld, addr);

	pasn->cipher = iwl_mld_cipher_to_location_cipher(cipher);

	expected_tk_len = iwl_mld_ftm_get_tk_len(mld, pasn->cipher);
	if (!expected_tk_len)
		goto out;

	/* If associated to this AP and already have security context,
	 * the TK is already configured for this station, so it
	 * shouldn't be set again here.
	 */
	if (!tk)
		expected_tk_len = 0;

	if (tk_len != expected_tk_len ||
	    (hltk_len && hltk_len != sizeof(pasn->hltk))) {
		IWL_ERR(mld, "Invalid key length: tk_len=%u hltk_len=%u\n",
			tk_len, hltk_len);
		goto out;
	}

	if (!expected_tk_len && !hltk_len) {
		IWL_ERR(mld, "TK and HLTK not set\n");
		goto out;
	}

	memcpy(pasn->addr, addr, sizeof(pasn->addr));

	if (hltk_len) {
		memcpy(pasn->hltk, hltk, sizeof(pasn->hltk));
		pasn->flags |= IWL_MLD_PASN_FLAG_HAS_HLTK;
	}

	if (tk && tk_len)
		memcpy(pasn->tk, tk, tk_len);

	list_add_tail(&pasn->list, &mld->ftm_initiator.pasn_list);
	return 0;
out:
	kfree(pasn);
	return -EINVAL;
}

void iwl_mld_ftm_initiator_init(struct iwl_mld *mld)
{
	INIT_LIST_HEAD(&mld->ftm_initiator.pasn_list);
	INIT_LIST_HEAD(&mld->ftm_initiator.loc_list);
}

void iwl_mld_ftm_initiator_stop(struct iwl_mld *mld)
{
	struct iwl_mld_ftm_pasn_entry *entry, *prev;

	lockdep_assert_wiphy(mld->wiphy);

	list_for_each_entry_safe(entry, prev, &mld->ftm_initiator.pasn_list,
				 list) {
		list_del(&entry->list);
		kfree(entry);
	}

	iwl_mld_ftm_reset_request(mld);
}

void iwl_mld_handle_lci_civic_notif(struct iwl_mld *mld,
				    struct iwl_rx_packet *pkt)
{
	const struct ieee80211_mgmt *mgmt = (void *)pkt->data;
	size_t len = iwl_rx_packet_payload_len(pkt);
	struct iwl_mld_lci_civic_entry *entry;
	const u8 *ies, *lci, *civic, *msr_ie;
	size_t ies_len, lci_len = 0, civic_len = 0;
	size_t baselen = IEEE80211_MIN_ACTION_SIZE(ftm);
	const u8 rprt_type_lci = IEEE80211_SPCT_MSR_RPRT_TYPE_LCI;
	const u8 rprt_type_civic = IEEE80211_SPCT_MSR_RPRT_TYPE_CIVIC;

	if (IWL_FW_CHECK(mld, len <= baselen,
			 "Invalid LCI/CIVIC notification length (%zu)\n", len))
		return;

	lockdep_assert_wiphy(mld->wiphy);

	ies = mgmt->u.action.ftm.variable;
	ies_len = len - baselen;

	msr_ie = cfg80211_find_ie_match(WLAN_EID_MEASURE_REPORT, ies, ies_len,
					&rprt_type_lci, 1, 4);
	if (msr_ie) {
		lci = msr_ie + 2;
		lci_len = msr_ie[1];
	}

	msr_ie = cfg80211_find_ie_match(WLAN_EID_MEASURE_REPORT, ies, ies_len,
					&rprt_type_civic, 1, 4);
	if (msr_ie) {
		civic = msr_ie + 2;
		civic_len = msr_ie[1];
	}

	entry = kmalloc(sizeof(*entry) + lci_len + civic_len, GFP_KERNEL);
	if (!entry)
		return;

	memcpy(entry->addr, mgmt->bssid, ETH_ALEN);

	entry->lci_len = lci_len;
	if (lci_len)
		memcpy(entry->buf, lci, lci_len);

	entry->civic_len = civic_len;
	if (civic_len)
		memcpy(entry->buf + lci_len, civic, civic_len);

	list_add_tail(&entry->list, &mld->ftm_initiator.loc_list);
}

void iwl_mld_ftm_abort(struct iwl_mld *mld, struct cfg80211_pmsr_request *req)
{
	struct iwl_tof_range_abort_cmd cmd = {
		.request_id = req->cookie,
	};

	lockdep_assert_wiphy(mld->wiphy);

	if (req != mld->ftm_initiator.req)
		return;

	if (iwl_mld_send_cmd_pdu(mld, WIDE_ID(LOCATION_GROUP,
					      TOF_RANGE_ABORT_CMD),
				 &cmd))
		IWL_ERR(mld, "failed to abort FTM process\n");

	iwl_mld_cancel_notifications_of_object(mld, IWL_MLD_OBJECT_TYPE_FTM_REQ,
					       mld->ftm_initiator.req->cookie);
	iwl_mld_ftm_reset_request(mld);
}

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018-2021 Intel Corporation
 */
#define pr_fmt(fmt) "iwlfmac: "fmt
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>

#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "fw/img.h"
#include "iwl-debug.h"
#include "iwl-drv.h"
#include "iwl-csr.h"
#include "iwl-phy-db.h"
#include "iwl-eeprom-parse.h"
#include "iwl-prph.h"
#include "iwl-io.h"
#include "iwl-nvm-parse.h"

#include "fmac.h"
#include "fw-api.h"
#include "debug.h"
#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
#include "iwl-dnt-cfg.h"
#include "iwl-dnt-dispatch.h"
#include "iwl-tm-gnl.h"
#endif


#define DRV_DESCRIPTION	"Intel(R) wireless full-MAC driver for Linux"
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_LICENSE("GPL");

static const struct iwl_op_mode_ops iwl_fmac_ops;
static void iwl_fmac_async_handlers_wk(struct work_struct *wk);

struct iwl_fmac_mod_params iwlfmac_mod_params = {
	.power_scheme = FMAC_PS_MODE_BALANCED,
	/* rest of fields are 0 by default */
};

MODULE_PARM_DESC(power_scheme,
		 "power management scheme: 1-active, 2-balanced, 3-low power (default: 1)");
module_param_named(power_scheme, iwlfmac_mod_params.power_scheme,
		   int, S_IRUGO);
MODULE_PARM_DESC(init_dbg,
		 "set to true to debug an ASSERT in INIT fw (default: false)");
module_param_named(init_dbg, iwlfmac_mod_params.init_dbg, bool, S_IRUGO);
module_param_named(amsdu_delay, iwlfmac_mod_params.amsdu_delay,
		   int, 0644);
MODULE_PARM_DESC(amsdu_delay,
		 "Delay (in milliseconds) to introduce for building A-MSDUs (default: 0)");

static int __init iwl_fmac_init(void)
{
	return iwl_opmode_register("iwlfmac", &iwl_fmac_ops);
}
module_init(iwl_fmac_init);

static void __exit iwl_fmac_exit(void)
{
	iwl_opmode_deregister("iwlfmac");
}
module_exit(iwl_fmac_exit);

u32 iwl_fmac_get_phy_config(struct iwl_fmac *fmac)
{
	u32 phy_config = ~(FW_PHY_CFG_TX_CHAIN | FW_PHY_CFG_RX_CHAIN);
	u32 valid_rx_ant = fmac->fw->valid_rx_ant;
	u32 valid_tx_ant = fmac->fw->valid_tx_ant;

	phy_config |= valid_tx_ant << FW_PHY_CFG_TX_CHAIN_POS |
		      valid_rx_ant << FW_PHY_CFG_RX_CHAIN_POS;

	return fmac->fw->phy_config & phy_config;
}

u8 iwl_fmac_get_valid_tx_ant(struct iwl_fmac *fmac)
{
	return fmac->nvm_data && fmac->nvm_data->valid_tx_ant ?
	       fmac->fw->valid_tx_ant & fmac->nvm_data->valid_tx_ant :
	       fmac->fw->valid_tx_ant;
}

static void iwl_fmac_nic_config(struct iwl_op_mode *op_mode)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	u8 radio_cfg_type, radio_cfg_step, radio_cfg_dash;
	u32 reg_val;
	u32 phy_config = iwl_fmac_get_phy_config(fmac);

	radio_cfg_type = (phy_config & FW_PHY_CFG_RADIO_TYPE) >>
			 FW_PHY_CFG_RADIO_TYPE_POS;
	radio_cfg_step = (phy_config & FW_PHY_CFG_RADIO_STEP) >>
			 FW_PHY_CFG_RADIO_STEP_POS;
	radio_cfg_dash = (phy_config & FW_PHY_CFG_RADIO_DASH) >>
			 FW_PHY_CFG_RADIO_DASH_POS;

	/* SKU control */
	reg_val = CSR_HW_REV_STEP_DASH(fmac->trans->hw_rev);

	/* radio configuration */
	reg_val |= radio_cfg_type << CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE;
	reg_val |= radio_cfg_step << CSR_HW_IF_CONFIG_REG_POS_PHY_STEP;
	reg_val |= radio_cfg_dash << CSR_HW_IF_CONFIG_REG_POS_PHY_DASH;

	WARN_ON((radio_cfg_type << CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE) &
		 ~CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE);

	iwl_trans_set_bits_mask(fmac->trans, CSR_HW_IF_CONFIG_REG,
				CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP_DASH |
				CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE |
				CSR_HW_IF_CONFIG_REG_MSK_PHY_STEP |
				CSR_HW_IF_CONFIG_REG_MSK_PHY_DASH |
				CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
				CSR_HW_IF_CONFIG_REG_BIT_MAC_SI,
				reg_val);

	IWL_DEBUG_INFO(fmac, "Radio type=0x%x-0x%x-0x%x\n", radio_cfg_type,
		       radio_cfg_step, radio_cfg_dash);
}

static void iwl_fmac_enable_txq(struct iwl_fmac *fmac, int queue, u16 ssn,
				const struct iwl_fmac_txq_scd_cfg *cfg,
				unsigned int wdg_timeout)
{
	int tid = cfg->tid;
	struct iwl_fmac_scd_txq_cfg_cmd cmd = {
		.vif_id = cfg->vif_id,
		.scd_queue = queue,
		.enable = 1,
		.aggregate = 1,
		.window = cfg->frame_limit,
		.sta_id = cfg->sta_id,
		.ssn = cpu_to_le16(ssn),
		.tx_fifo = cfg->fifo,
		.tid = tid,
	};
	struct iwl_fmac_sta *sta;

	if (WARN_ON(cfg->sta_id >= IWL_FMAC_MAX_STA))
		return;

	/* Make sure this TID isn't already enabled on this STA */
	sta = rcu_dereference_protected(fmac->stas[cfg->sta_id],
					lockdep_is_held(&fmac->mutex));

	if (WARN_ON(sta->tids[tid].txq_id != IWL_FMAC_INVALID_TXQ_ID)) {
		IWL_ERR(fmac, "TID %d already assigned to TXQ #%d\n", tid,
			sta->tids[tid].txq_id);
		return;
	}

	sta->tids[tid].txq_id = queue;

	IWL_DEBUG_TX_QUEUES(fmac, "Enabling TXQ #%d for sta_id %d tid %d\n",
			    queue, cfg->sta_id, tid);

	iwl_trans_txq_enable_cfg(fmac->trans, queue, ssn, NULL, wdg_timeout);
	WARN(iwl_fmac_send_cmd_pdu(fmac,
				   WIDE_ID(FMAC_GROUP, FMAC_SCD_QUEUE_CFG), 0,
				   sizeof(cmd), &cmd),
	     "Failed to configure queue %d on FIFO %d\n", queue, cfg->fifo);
}

static void iwl_fmac_disable_txq_old(struct iwl_fmac *fmac,
				     struct iwl_fmac_sta *sta,
				     int queue)
{
	struct iwl_fmac_scd_txq_cfg_cmd cmd = {
		.vif_id = sta->vif->id,
		.sta_id = sta->sta_id,
		.scd_queue = queue,
		.enable = 0,
	};
	int ret;

	IWL_DEBUG_TX_QUEUES(fmac, "Disabling TXQ #%d\n", queue);

	iwl_trans_txq_disable(fmac->trans, queue, false);
	ret = iwl_fmac_send_cmd_pdu(fmac,
				    WIDE_ID(FMAC_GROUP, FMAC_SCD_QUEUE_CFG),
				    0, sizeof(cmd), &cmd);
	if (ret)
		IWL_ERR(fmac, "Failed to disable queue %d (ret=%d)\n",
			queue, ret);
}

static void iwl_fmac_disable_txq(struct iwl_fmac *fmac,
				 struct iwl_fmac_sta *sta,
				 int queue)
{
	if (!iwl_fmac_has_new_tx_api(fmac))
		return iwl_fmac_disable_txq_old(fmac, sta, queue);
	iwl_trans_txq_free(fmac->trans, queue);
}

void iwl_fmac_disconnected(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			   __le16 reason, u8 locally_generated)
{
	struct iwl_fmac_vif *vif = sta->vif;
	struct wireless_dev *wdev = &vif->wdev;

	/*
	 * this happens when we have allocation failures during
	 * connect processing and have to disconnect to sync up
	 */
	if (vif->u.mgd.connect_state == IWL_FMAC_CONNECT_CONNECTING)
		return;

	if (WARN(vif->u.mgd.connect_state != IWL_FMAC_CONNECT_CONNECTED,
		 "state: %d", vif->u.mgd.connect_state))
		return;

	vif_info(vif, "Disconnected from %pM\n", sta->addr);

	/*
	 * If the disconnection was initiated by cfg80211, the queues are
	 * stopped already, but not in case the disconnection comes from
	 * the firmware.
	 */
	netif_tx_stop_all_queues(wdev->netdev);
	RCU_INIT_POINTER(vif->u.mgd.ap_sta, NULL);
	iwl_fmac_free_sta(fmac, sta->sta_id, false);
	vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;
	netif_carrier_off(wdev->netdev);
	cfg80211_disconnected(wdev->netdev, le16_to_cpu(reason), NULL, 0,
			      locally_generated, GFP_KERNEL);
}

static void iwl_fmac_rx_disconnected(struct iwl_fmac *fmac,
				     struct iwl_rx_cmd_buffer *rxb)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_disconnect_cmd *notify = (void *)&pkt->data;
	struct wireless_dev *wdev;

	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		struct iwl_fmac_vif *vif = vif_from_wdev(wdev);
		struct iwl_fmac_sta *sta;

		if (vif->id != notify->vif_id)
			continue;

		sta = rcu_dereference_protected(vif->u.mgd.ap_sta,
						lockdep_is_held(&fmac->mutex));

		if (WARN_ON_ONCE(!sta))
			break;

		iwl_fmac_disconnected(fmac, sta, notify->reason,
				      notify->locally_generated);
	}
}

static void iwl_fmac_tlc_update_notif(struct iwl_fmac *fmac,
				      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_tlc_update_notif *notif;
	struct iwl_fmac_sta *sta;
	u32 flags;

	rcu_read_lock();

	notif = (void *)pkt->data;
	sta = rcu_dereference(fmac->stas[notif->sta_id]);
	if (IS_ERR_OR_NULL(sta))
		goto out;

	flags = le32_to_cpu(notif->flags);

	if (flags & IWL_TLC_NOTIF_FLAG_RATE)
		IWL_DEBUG_RATE(fmac, "new rate_n_flags: 0x%X\n",
			       le32_to_cpu(notif->rate));

	if (flags & IWL_TLC_NOTIF_FLAG_AMSDU) {
		sta->amsdu_enabled = le32_to_cpu(notif->amsdu_enabled);
		sta->amsdu_size = le32_to_cpu(notif->amsdu_size);

		IWL_DEBUG_RATE(fmac,
			       "AMSDU update. AMSDU size: %d, AMSDU TID bitmap 0x%X\n",
			       sta->amsdu_size, sta->amsdu_enabled);
	}

out:
	rcu_read_unlock();
}

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
static void iwl_fmac_rx_fw_logs(struct iwl_fmac *fmac,
				struct iwl_rx_cmd_buffer *rxb)
{
	iwl_dnt_dispatch_collect_ucode_message(fmac->trans, rxb);
}
#endif

static void iwl_fmac_rx_scan_complete(struct iwl_fmac *fmac,
				      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_scan_complete_notif *notif = (void *)&pkt->data;
	struct cfg80211_scan_info info = {
		.aborted = notif->aborted,
	};

	if (WARN_ON(!fmac->scan_request))
		return;

	IWL_DEBUG_SCAN(fmac, "Scan complete. aborted %d\n", info.aborted);
	cfg80211_scan_done(fmac->scan_request, &info);
	fmac->scan_request = NULL;
}

static void iwl_fmac_fail_connection(struct iwl_fmac *fmac,
				     struct iwl_fmac_vif *vif,
				     const u8 *bssid, bool disconnection)
{
	/*
	 * fail a successful connection - tell cfg80211 about
	 * a connection failure, and ask the fw to disconnect
	 */
	struct iwl_fmac_disconnect_cmd disconnect = {
		.vif_id = vif->id,
		.reason = cpu_to_le16(WLAN_REASON_UNSPECIFIED),
	};

	iwl_fmac_send_cmd_pdu(fmac, WIDE_ID(FMAC_GROUP, FMAC_DISCONNECT),
			      0, sizeof(disconnect),
			      &disconnect);

	if (disconnection) {
		netif_carrier_off(vif->wdev.netdev);
		netif_tx_stop_all_queues(vif->wdev.netdev);
		synchronize_net();
		cfg80211_disconnected(vif->wdev.netdev, 0, NULL, 0, 0,
				      GFP_KERNEL);
	} else {
		cfg80211_connect_timeout(vif->wdev.netdev, bssid,
					 NULL, 0, GFP_KERNEL,
					 NL80211_TIMEOUT_UNSPECIFIED);
	}

	vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;
}

static void iwl_fmac_set_wep_tx_key(struct iwl_fmac *fmac,
				    struct iwl_fmac_sta *sta,
				    u8 wep_tx_keidx)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sta->ptk); i++) {
		struct iwl_fmac_sta_key *ptk;

		ptk = rcu_dereference_protected(sta->ptk[i],
						lockdep_is_held(&fmac->mutex));

		if (ptk && (ptk->cipher == IWL_FMAC_CIPHER_WEP104 ||
			    ptk->cipher == IWL_FMAC_CIPHER_WEP40)) {
			sta->ptk_idx = wep_tx_keidx;
			return;
		}
	}
}

static void iwl_fmac_set_sta_keys(struct iwl_fmac *fmac,
				  struct iwl_fmac_sta *sta,
				  struct iwl_fmac_keys *keys)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(keys->ptk); i++) {
		struct iwl_fmac_key *key = &keys->ptk[i];

		if (!key->valid)
			continue;

		iwl_fmac_sta_add_key(fmac, sta, true, key);
	}
	iwl_fmac_set_wep_tx_key(fmac, sta, keys->wep_tx_keyidx);

	for (i = 0; i < ARRAY_SIZE(keys->gtk); i++) {
		struct iwl_fmac_key *key = &keys->gtk[i];

		if (!key->valid)
			continue;

		iwl_fmac_sta_add_key(fmac, sta, false, key);
	}
}

static void iwl_fmac_cleanup_ap_sta(struct iwl_fmac *fmac,
				    struct iwl_fmac_vif *vif, int warn)
{
	struct iwl_fmac_sta *ap_sta;
	struct wireless_dev *wdev = &vif->wdev;
	int i;

	ap_sta = rcu_dereference_protected(vif->u.mgd.ap_sta,
					   lockdep_is_held(&fmac->mutex));
	if (ap_sta) {
		/*
		 * stop the queues because the station was already removed in FW
		 * so we are throwing packets
		 */
		for (i = 0; i < AC_NUM; i++)
			iwl_fmac_stop_ac_queue(fmac, wdev, i);

		RCU_INIT_POINTER(vif->u.mgd.ap_sta, NULL);
		iwl_fmac_free_sta(fmac, ap_sta->sta_id, false);
	} else if (warn) {
		WARN_ON(1);
	}
}

static int iwl_fmac_connect_result_common(struct iwl_fmac_vif *vif,
					  struct iwl_fmac_connect_result *res)
{
	struct iwl_fmac *fmac = vif->fmac;
	struct cfg80211_bss *bss = NULL;
	enum cfg80211_bss_frame_type ftype;
	struct iwl_fmac_sta *sta;
	const u8 *ies;
	size_t ie_len;
	struct cfg80211_inform_bss data = {
		.chan = ieee80211_get_channel(wiphy_from_fmac(fmac),
					      le16_to_cpu(res->center_freq)),
		.scan_width = NL80211_BSS_CHAN_WIDTH_20,
		.signal = le32_to_cpu(res->signal),
	};
	int ret;

	/* update bss data - prefer the probe-resp IEs */
	if (res->presp_ielen) {
		ftype = CFG80211_BSS_FTYPE_PRESP;
		ies = res->ie_data;
		ie_len = le32_to_cpu(res->presp_ielen);
	} else if (res->beacon_ielen) {
		ftype = CFG80211_BSS_FTYPE_BEACON;
		ies = res->ie_data;
		ie_len = le32_to_cpu(res->beacon_ielen);
	} else {
		WARN_ON(1);
		return -EINVAL;
	}

	bss = cfg80211_inform_bss_data(wiphy_from_fmac(fmac), &data,
				       ftype, res->bssid,
				       le64_to_cpu(res->tsf),
				       le16_to_cpu(res->capability),
				       le16_to_cpu(res->beacon_int),
				       ies, ie_len, GFP_KERNEL);
	if (!bss) {
		vif_info(vif, "Can't connect - invalid bss data\n");
		return -EINVAL;
	}

	/* In case of external authentication we already should have a sta */
	sta = rcu_dereference_protected(fmac->stas[res->sta_id],
					lockdep_is_held(&fmac->mutex));
	if (!sta) {
		ret = iwl_fmac_alloc_sta(fmac, vif, res->sta_id,
					 res->bssid);
		if (ret)
			return ret;

		sta = rcu_dereference_protected(fmac->stas[res->sta_id],
						lockdep_is_held(&fmac->mutex));
	}

	sta->qos = res->qos;
	sta->authorized = res->authorized;
	if (cfg80211_find_ext_ie(WLAN_EID_EXT_HE_CAPABILITY, ies, ie_len))
		sta->he = true;
	if (!data.chan)
		return -EINVAL;
	sta->band = data.chan->band;
	rcu_assign_pointer(vif->u.mgd.ap_sta, sta);

	iwl_fmac_set_sta_keys(fmac, sta, &res->keys);

	if (res->qos) {
		vif->u.mgd.wmm_acm |= res->bk_acm ? BIT(1) | BIT(2)
			: vif->u.mgd.wmm_acm;
		vif->u.mgd.wmm_acm |= res->vi_acm ? BIT(4) | BIT(5)
			: vif->u.mgd.wmm_acm;
		vif->u.mgd.wmm_acm |= res->vo_acm ? BIT(6) | BIT(7)
			: vif->u.mgd.wmm_acm;
		vif->u.mgd.wmm_acm |= res->be_acm ? BIT(0) | BIT(3)
			: vif->u.mgd.wmm_acm;
	}

	cfg80211_put_bss(wiphy_from_fmac(fmac), bss);

	return 0;
}

static void iwl_fmac_connect_result(struct iwl_fmac_vif *vif,
				    struct iwl_fmac_connect_result *result)
{
	struct iwl_fmac *fmac = vif->fmac;
	struct wireless_dev *wdev = &vif->wdev;
	const u8 *req_ies, *resp_ies;
	u32 assoc_req_ie_len, assoc_resp_ie_len, assoc_req_var_len;
	u32 assoc_resp_var_len;

	/* This code is temp, until API change is complete */
	if (result->reassoc)
		assoc_req_var_len =
			offsetof(struct ieee80211_mgmt,
				 u.reassoc_req.variable);
	else
		assoc_req_var_len =
			offsetof(struct ieee80211_mgmt,
				 u.assoc_req.variable);
	assoc_req_var_len -= sizeof(struct ieee80211_hdr_3addr);
	assoc_req_ie_len = 0;
	if (le32_to_cpu(result->assoc_req_ie_len) > assoc_req_var_len)
		assoc_req_ie_len = le32_to_cpu(result->assoc_req_ie_len) -
			assoc_req_var_len;

	assoc_resp_var_len = offsetof(struct ieee80211_mgmt,
				      u.assoc_resp.variable) -
				 sizeof(struct ieee80211_hdr_3addr);
	assoc_resp_ie_len = 0;
	if (le32_to_cpu(result->assoc_resp_ie_len) > assoc_resp_var_len)
		assoc_resp_ie_len = le32_to_cpu(result->assoc_resp_ie_len) -
			assoc_resp_var_len;

	req_ies = result->ie_data +
		le32_to_cpu(result->presp_ielen) +
		le32_to_cpu(result->beacon_ielen);
	resp_ies = req_ies + le32_to_cpu(result->assoc_req_ie_len);

	if (result->not_found) {
		/* We might have added AP sta for external auth */
		iwl_fmac_cleanup_ap_sta(fmac, vif, 0);
		cfg80211_connect_timeout(wdev->netdev, NULL,
					 req_ies, assoc_req_ie_len,
					 GFP_KERNEL,
					 NL80211_TIMEOUT_SCAN);
		vif_info(vif, "Can't connect - not found\n");
		vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;
		return;
	}

	if (result->status != cpu_to_le16(WLAN_STATUS_SUCCESS)) {
		/* We might have added AP sta for external auth */
		iwl_fmac_cleanup_ap_sta(fmac, vif, 0);
		cfg80211_connect_result(wdev->netdev, result->bssid,
					req_ies, assoc_req_ie_len,
					resp_ies, assoc_resp_ie_len,
					le16_to_cpu(result->status),
					GFP_KERNEL);
		vif_info(vif, "Can't connect: %d\n",
			 le16_to_cpu(result->status));
		vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;
		return;
	}

	if (iwl_fmac_connect_result_common(vif, result)) {
		iwl_fmac_fail_connection(fmac, vif, result->bssid, false);
		return;
	}

	cfg80211_connect_result(wdev->netdev, result->bssid,
				req_ies, assoc_req_ie_len,
				resp_ies, assoc_resp_ie_len,
				WLAN_STATUS_SUCCESS, GFP_KERNEL);
	vif->u.mgd.connect_state = IWL_FMAC_CONNECT_CONNECTED;

	if (result->authorized)
		cfg80211_port_authorized(wdev->netdev, result->bssid,
					 GFP_KERNEL);

	vif_info(vif, "Connected to %pM\n", result->bssid);

	netif_carrier_on(wdev->netdev);
	netif_tx_start_all_queues(wdev->netdev);
}

static void iwl_fmac_roam_result(struct iwl_fmac_vif *vif,
				 struct iwl_fmac_connect_result *result)
{
	struct iwl_fmac *fmac = vif->fmac;
	struct wireless_dev *wdev = &vif->wdev;
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	int i;
	struct cfg80211_roam_info info;

	if (result->status != cpu_to_le16(WLAN_STATUS_SUCCESS)) {
		struct iwl_fmac_sta *ap_sta =
			rcu_dereference_protected(vif->u.mgd.ap_sta,
						  lockdep_is_held(&fmac->mutex));
		if (ap_sta)
			vif_info(vif, "Disconnected from %pM\n", ap_sta->addr);
	}

	/*
	 * FW roamed to a new BSS, the previous AP station is
	 * not valid anymore.
	 */
	iwl_fmac_cleanup_ap_sta(fmac, vif, 1);

	if (result->status != cpu_to_le16(WLAN_STATUS_SUCCESS)) {
		flush_work(&fmac->add_stream_wk);
		netif_carrier_off(wdev->netdev);
		netif_tx_stop_all_queues(wdev->netdev);
		synchronize_net();
		vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;
		cfg80211_disconnected(wdev->netdev, 0, NULL, 0, 0, GFP_KERNEL);
		return;
	}

	if (iwl_fmac_connect_result_common(vif, result)) {
		iwl_fmac_fail_connection(fmac, vif, result->bssid, true);
		return;
	}

	/* AP station has been added so we can wake the queues now */
	for (i = 0; i < AC_NUM; i++)
		iwl_fmac_wake_ac_queue(fmac, wdev, i);

	info.channel = ieee80211_get_channel(wiphy,
					     le16_to_cpu(result->center_freq));
	if (!info.channel) {
		vif_info(vif, "Can't connect - invalid frequency\n");
		iwl_fmac_fail_connection(fmac, vif, result->bssid, true);
		return;
	}

	info.req_ie_len = le32_to_cpu(result->assoc_req_ie_len);
	info.resp_ie_len = le32_to_cpu(result->assoc_resp_ie_len);
	info.req_ie = result->ie_data + le32_to_cpu(result->presp_ielen) +
		le32_to_cpu(result->beacon_ielen);
	info.resp_ie = info.req_ie + info.req_ie_len;

	info.bss = NULL;
	info.bssid = result->bssid;

	cfg80211_roamed(wdev->netdev, &info, GFP_KERNEL);

	if (result->authorized)
		cfg80211_port_authorized(wdev->netdev, result->bssid,
					 GFP_KERNEL);

	vif_info(vif, "Connected to %pM\n", result->bssid);
}

static void iwl_fmac_rx_connect_result(struct iwl_fmac *fmac,
				       struct iwl_rx_cmd_buffer *rxb)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_connect_result *result = (void *)&pkt->data;
	struct wireless_dev *wdev;
	struct iwl_fmac_vif *vif;

	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		vif = vif_from_wdev(wdev);
		if (vif->id != result->vif_id)
			continue;

		if (WARN(vif->u.mgd.connect_state == IWL_FMAC_CONNECT_IDLE,
			 "state: %d", vif->u.mgd.connect_state))
			break;

		if (vif->u.mgd.connect_state == IWL_FMAC_CONNECT_CONNECTED)
			iwl_fmac_roam_result(vif, result);
		else
			iwl_fmac_connect_result(vif, result);

		break;
	}
}

static void iwl_fmac_rx_keys_update(struct iwl_fmac *fmac,
				    struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_keys_update_notif *notif = (void *)&pkt->data;
	struct iwl_fmac_sta *sta;

	sta = rcu_dereference_protected(fmac->stas[notif->sta_id],
					lockdep_is_held(&fmac->mutex));
	if (WARN_ON_ONCE(!sta))
		return;

	iwl_fmac_set_sta_keys(fmac, sta, &notif->keys);

	if (sta->authorized)
		return;

	if (WARN_ON(sta->vif->u.mgd.connect_state !=
		    IWL_FMAC_CONNECT_CONNECTED))
		return;

	cfg80211_port_authorized(sta->vif->wdev.netdev, sta->addr, GFP_KERNEL);
	sta->authorized = true;
}

static void iwl_fmac_rx_reg_update(struct iwl_fmac *fmac,
				   struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_reg_resp *rsp = (void *)&pkt->data;
	struct ieee80211_regdomain *regd;

	IWL_DEBUG_LAR(fmac,
		      "received mcc update: mcc (0x%x, 0x%x) src %d\n",
		      __le16_to_cpu(rsp->mcc) >> 8,
		      __le16_to_cpu(rsp->mcc) & 0xff,
		      rsp->source_id);
	regd = iwl_parse_nvm_mcc_info(fmac->dev, fmac->cfg,
				      __le32_to_cpu(rsp->n_channels),
				      rsp->channels,
				      __le16_to_cpu(rsp->mcc), 0, 0, 0);
	if (IS_ERR_OR_NULL(regd)) {
		IWL_ERR(fmac, "Could not parse notif from FW %d\n",
			PTR_ERR_OR_ZERO(regd));
		return;
	}

	IWL_DEBUG_LAR(fmac,
		      "setting alpha2 from FW to %s (0x%x, 0x%x) src=%d\n",
		      regd->alpha2, regd->alpha2[0], regd->alpha2[1],
		      rsp->source_id);
	regulatory_set_wiphy_regd(wiphy_from_fmac(fmac), regd);
	kfree(regd);
}

static void iwl_fmac_rx_eapol(struct iwl_fmac *fmac,
			      struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_rx_eapol_notif *eapol = (void *)&pkt->data;
	struct iwl_fmac_sta *sta;
	struct sk_buff *skb;
	struct ethhdr ehdr;
	u16 len = le16_to_cpu(eapol->len);

	skb = alloc_skb(sizeof(ehdr) + len, GFP_ATOMIC);
	if (!skb)
		return;

	rcu_read_lock();
	sta = iwl_get_sta(fmac, eapol->addr);
	if (WARN_ON(!sta))
		goto out;

	memcpy(ehdr.h_dest, sta->vif->addr, ETH_ALEN);
	memcpy(ehdr.h_source, eapol->addr, ETH_ALEN);
	ehdr.h_proto = cpu_to_be16(ETH_P_PAE);

	memcpy(skb_put(skb, sizeof(ehdr)), &ehdr, sizeof(ehdr));
	memcpy(skb_put(skb, len), eapol->data, len);

	skb->protocol = eth_type_trans(skb, sta->vif->wdev.netdev);
	rcu_read_unlock();

	netif_receive_skb(skb);
	return;
out:
	rcu_read_unlock();
	kfree_skb(skb);
}

static void iwl_fmac_rx_send_frame(struct iwl_fmac *fmac,
				   struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_send_frame_notif *send_frame = (void *)&pkt->data;
	u16 len = le16_to_cpu(send_frame->len);

	if (WARN_ON(iwl_rx_packet_payload_len(pkt) <
	    len + sizeof(*send_frame)))
		return;

	iwl_fmac_tx_send_frame(fmac, send_frame);
}

int iwl_fmac_add_mcast_sta(struct iwl_fmac *fmac,
			   struct iwl_fmac_vif *vif,
			   struct iwl_fmac_sta *sta,
			   u8 sta_id,
			   struct iwl_fmac_keys *keys,
			   u8 mq_id, bool bcast)
{
	int i;

	spin_lock_init(&sta->lock);
	sta->vif = vif;
	sta->sta_id = sta_id;
	sta->authorized = true;
	memcpy(sta->addr, MCAST_STA_ADDR, ETH_ALEN);

	if (keys)
		iwl_fmac_set_sta_keys(fmac, sta, keys);

	rcu_assign_pointer(fmac->stas[sta_id], sta);

	for (i = 0; i < ARRAY_SIZE(sta->tids); i++) {
		sta->tids[i].txq_id = IWL_FMAC_INVALID_TXQ_ID;
		skb_queue_head_init(&sta->tids[i].deferred_tx_frames);
	}

	if (!iwl_fmac_has_new_tx_api(fmac)) {
		struct iwl_fmac_txq_scd_cfg cfg = {
			.frame_limit = IWL_FRAME_LIMIT,
		};

		IWL_DEBUG_TX_QUEUES(fmac,
				    "Allocating mcast queue #%d to sta %d\n",
				    mq_id, sta_id);

		/* Make sure this TXQ wasn't already allocated to someone */
		if (WARN_ON(fmac->queue_sta_map[mq_id] !=
			    IWL_FMAC_INVALID_STA_ID)) {
			IWL_ERR(fmac,
				"Trying to allocate mcast TXQ %d in use\n",
				mq_id);
			return -1;
		}

		fmac->queue_sta_map[mq_id] = sta_id;

		cfg.vif_id = vif->id;
		cfg.fifo = bcast ? IWL_FMAC_TX_FIFO_VO :
				   IWL_FMAC_TX_FIFO_MCAST;
		cfg.sta_id = sta_id;
		cfg.tid = 0;
		/* TODO: set timeout without hardcoding the value */
		iwl_fmac_enable_txq(fmac, mq_id, 0, &cfg, 10000);
	}

	return 0;
}

static void iwl_fmac_restart_station(struct iwl_fmac *fmac,
				     struct wireless_dev *wdev)
{
	struct iwl_fmac_vif *vif = vif_from_wdev(wdev);
	struct iwl_fmac_sta *sta;

	if (vif->u.mgd.connect_state == IWL_FMAC_CONNECT_CONNECTING) {
		cfg80211_connect_timeout(wdev->netdev, NULL, NULL, 0,
					 GFP_KERNEL,
					 NL80211_TIMEOUT_UNSPECIFIED);
		vif_info(vif, "Connection attempt failed\n");
		vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;
	}

	sta = rcu_dereference_protected(vif->u.mgd.ap_sta,
					lockdep_is_held(&fmac->mutex));
	if (!sta)
		return;

	if (vif->u.mgd.connect_state == IWL_FMAC_CONNECT_CONNECTED) {
		/* Queues were already stopped */
		netif_carrier_off(wdev->netdev);
		cfg80211_disconnected(wdev->netdev,
				      WLAN_REASON_DEAUTH_LEAVING,
				      NULL, 0, true, GFP_KERNEL);
		vif_info(vif, "Disconnected from %pM\n", sta->addr);
	}

	RCU_INIT_POINTER(vif->u.mgd.ap_sta, NULL);
	/* this will also call to synchronize_net() */
	iwl_fmac_free_sta(fmac, sta->sta_id, true);
	vif->u.mgd.connect_state = IWL_FMAC_CONNECT_IDLE;

	iwl_fmac_send_config_u32(fmac, vif->id,
				 IWL_FMAC_CONFIG_VIF_POWER_DISABLED,
				 wdev->ps ? 0 : 1);

	iwl_fmac_send_config_u32(fmac, vif->id,
				 IWL_FMAC_CONFIG_VIF_TXPOWER_USER,
				 vif->user_power_level);
}

void iwl_fmac_remove_mcast_sta(struct iwl_fmac *fmac,
			       struct iwl_fmac_sta *mc_sta)
{
	u16 mcast_queue = mc_sta->tids[0].txq_id;

	if (mcast_queue != IWL_FMAC_INVALID_TXQ_ID) {
		fmac->queue_sta_map[mcast_queue] =
			IWL_FMAC_INVALID_STA_ID;
		RCU_INIT_POINTER(fmac->stas[mc_sta->sta_id], NULL);
		iwl_fmac_flush_sta_queues(fmac, mc_sta);
		iwl_fmac_disable_txq(fmac, mc_sta, mcast_queue);
	}

	iwl_fmac_destroy_sta_keys(fmac, mc_sta);
	mc_sta->encryption = false;
}

#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
/* A stub notification handler to receive the profiling report.
 * The notification handler is empty because the report is processed by
 * trace-cmd and not by the driver
 */
static void iwl_fmac_rx_dhc(struct iwl_fmac *fmac,
			    struct iwl_rx_cmd_buffer *rxb)
{
	IWL_DEBUG_INFO(fmac, "profiling notification received\n");
}
#endif /* CPTCFG_IWLWIFI_DHC_PRIVATE */

void iwl_fmac_nic_restart(struct iwl_fmac *fmac)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct wireless_dev *wdev;
	struct cfg80211_scan_info info = {
		.aborted = true,
	};
	int ret = 0;
	int i;

	iwl_abort_notification_waits(&fmac->notif_wait);
	iwl_dbg_tlv_del_timers(fmac->trans);

	flush_work(&fmac->add_stream_wk);

	mutex_lock(&fmac->mutex);

	iwl_fmac_stop_device(fmac);

	for (i = 0; i < ARRAY_SIZE(fmac->stas); i++) {
		struct iwl_fmac_sta *sta =
			rcu_dereference_protected(fmac->stas[i],
						  lockdep_is_held(&fmac->mutex));
		if (!sta)
			continue;

		iwl_fmac_destroy_sta_tids(fmac, sta, true);

		for (i = 0; i < ARRAY_SIZE(sta->amsdu); i++) {
			if (sta->amsdu[i].skb)
				dev_kfree_skb(sta->amsdu[i].skb);
		}
	}

	memset(fmac->queue_sta_map, IWL_FMAC_INVALID_STA_ID,
	       sizeof(fmac->queue_sta_map));
	memset(&fmac->sta_deferred_frames, 0,
	       sizeof(fmac->sta_deferred_frames));

	for (i = 0; i < IWL_MAX_BAID; i++) {
		int q;

		for (q = 0; q < fmac->trans->num_rx_queues; q++) {
			struct iwl_fmac_reorder_buffer *buffer =
				&fmac->reorder_bufs[i][q];
			struct iwl_fmac_sta *sta;

			if (buffer->sta_id == IWL_FMAC_INVALID_STA_ID)
				continue;

			sta = rcu_dereference_protected(fmac->stas[buffer->sta_id],
					  lockdep_is_held(&fmac->mutex));

			iwl_fmac_destroy_reorder_buffer(fmac, sta, buffer);
		}
	}

	/* handle ongoing scan */
	if (fmac->scan_request) {
		cfg80211_scan_done(fmac->scan_request, &info);
		fmac->scan_request = NULL;
	}

	if (!atomic_read(&fmac->open_count))
		goto out_unlock;

	IWL_ERR(fmac, "Restarting firmware\n");

	ret = iwl_fmac_run_rt_fw(fmac);
	if (ret) {
		if (ret != -ERFKILL)
			iwl_fw_dbg_error_collect(&fmac->fwrt,
						 FW_DBG_TRIGGER_DRIVER);
		goto out_unlock;
	}

	/* if there were any vifs - add them back */
	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		struct iwl_fmac_vif *vif = vif_from_wdev(wdev);

		struct iwl_fmac_add_vif_cmd cmd = {};
		struct iwl_fmac_add_vif_resp *resp;
		struct iwl_host_cmd hcmd = {
			.id = WIDE_ID(FMAC_GROUP, FMAC_ADD_VIF),
			.flags = CMD_WANT_SKB,
			.data = { &cmd, },
			.len = { sizeof(cmd) },
		};

		cmd.type = iwl_fmac_nl_to_fmac_type(vif->wdev.iftype);
		ether_addr_copy(cmd.addr, wdev->netdev->dev_addr);

		ret = iwl_fmac_send_cmd(fmac, &hcmd);
		if (ret)
			goto out_unlock;

		resp = (void *)hcmd.resp_pkt->data;
		if (resp->status != IWL_ADD_VIF_SUCCESS) {
			ret = resp->status;
			iwl_free_resp(&hcmd);
			goto out_unlock;
		}
		vif->id = resp->id;
		switch (wdev->iftype) {
			case NL80211_IFTYPE_STATION:
				iwl_fmac_restart_station(fmac, wdev);
				break;
			default:
				WARN_ON(1);
				break;
		}
	}

out_unlock:
	if (ret) {
		IWL_ERR(fmac, "Recovery from HW error failed\n");
		iwl_fmac_stop_device(fmac);
	}
	mutex_unlock(&fmac->mutex);
}

static void iwl_fmac_nic_restart_wk(struct work_struct *work)
{
	struct iwl_fmac *fmac =
		container_of(work, struct iwl_fmac, restart_wk);

	if (!iwlwifi_mod_params.fw_restart)
		return;

	iwl_fw_flush_dumps(&fmac->fwrt);

	/*
	 * We are going to free all the Tx / Rx queues,
	 * make sure we don't have packets on the way.
	 */
	synchronize_net();

	rtnl_lock();
	iwl_fmac_nic_restart(fmac);
	rtnl_unlock();
}

static void iwl_fmac_external_auth_request(struct iwl_fmac *fmac,
					   struct iwl_rx_cmd_buffer *rxb)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_external_auth *auth = (void *)&pkt->data;
	struct wireless_dev *wdev;

	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		struct iwl_fmac_vif *vif = vif_from_wdev(wdev);
		struct cfg80211_external_auth_params params = {};
		struct iwl_fmac_sta *ap_sta;

		if (vif->id != auth->vif_id)
			continue;

		if (WARN(vif->u.mgd.connect_state !=
			 IWL_FMAC_CONNECT_CONNECTING,
			 "state: %d", vif->u.mgd.connect_state))
			break;

		params.action = auth->action;
		params.key_mgmt_suite = le32_to_cpu(auth->key_mgmt_suite);
		params.status = le16_to_cpu(auth->status);
		memcpy(params.bssid, auth->bssid, ETH_ALEN);
		params.ssid.ssid_len = auth->ssid_len;
		if (auth->ssid_len)
			memcpy(params.ssid.ssid, auth->ssid,
			       sizeof(params.ssid.ssid));

		/* If we are roaming, cleanup previous AP sta */
		iwl_fmac_cleanup_ap_sta(fmac, vif, 0);

		if (WARN_ON(iwl_fmac_alloc_sta(fmac, vif, auth->ap_sta_id,
					       auth->bssid)))
			return;

		ap_sta = rcu_dereference_protected(fmac->stas[auth->ap_sta_id],
						lockdep_is_held(&fmac->mutex));
		ap_sta->band = le16_to_cpu(auth->ap_freq) > 5000 ?
			       NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
		rcu_assign_pointer(vif->u.mgd.ap_sta, ap_sta);

		WARN_ON(cfg80211_external_auth_request(wdev->netdev, &params,
						       GFP_KERNEL));
		break;
	}
}

static void iwl_fmac_external_auth_rx_mgmt(struct iwl_fmac *fmac,
					   struct iwl_rx_cmd_buffer *rxb)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_fmac_rx_external_auth *auth = (void *)&pkt->data;
	struct wireless_dev *wdev;

	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		struct iwl_fmac_vif *vif = vif_from_wdev(wdev);

		if (vif->id != auth->vif_id)
			continue;

		if (WARN(vif->u.mgd.connect_state !=
			 IWL_FMAC_CONNECT_CONNECTING,
			 "state: %d", vif->u.mgd.connect_state))
			break;

		cfg80211_rx_mgmt(wdev, le32_to_cpu(auth->freq),
				 (s8)auth->signal, auth->data,
				 le16_to_cpu(auth->len), 0);
		break;
	}
}

/**
 * enum iwl_rx_handler_context context for Rx handler
 * @RX_HANDLER_SYNC : this means that it will be called in the Rx path
 *	which can't acquire fmac->mutex.
 * @RX_HANDLER_ASYNC_LOCKED : If the handler needs to hold fmac->mutex
 *	(and only in this case!), it should be set as ASYNC. In that case,
 *	it will be called from a worker with fmac->mutex held.
 */
enum iwl_rx_handler_context {
	RX_HANDLER_SYNC,
	RX_HANDLER_ASYNC_LOCKED,
};

/**
 * struct iwl_rx_handlers handler for FW notification
 * @cmd_id: command id
 * @context: see &iwl_rx_handler_context
 * @fn: the function is called when notification is received
 */
struct iwl_rx_handlers {
	u16 cmd_id;
	enum iwl_rx_handler_context context;
	void (*fn)(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb);
};

#define RX_HANDLER(_cmd_id, _fn, _context)	\
	{ .cmd_id = _cmd_id, .fn = _fn, .context = _context }
#define RX_HANDLER_GRP(_grp, _cmd, _fn, _context)	\
	{ .cmd_id = WIDE_ID(_grp, _cmd), .fn = _fn, .context = _context }

/*
 * Handlers for fw notifications
 * Convention: RX_HANDLER(CMD_NAME, iwl_fmac_rx_CMD_NAME
 * This list should be in order of frequency for performance purposes.
 *
 * The handler can be one from three contexts, see &iwl_rx_handler_context
 */
static const struct iwl_rx_handlers iwl_fmac_rx_handlers[] = {
	RX_HANDLER(TX_CMD, iwl_fmac_rx_tx_cmd, RX_HANDLER_SYNC),
	RX_HANDLER(BA_NOTIF, iwl_fmac_rx_ba_notif, RX_HANDLER_SYNC),
	RX_HANDLER_GRP(DATA_PATH_GROUP, TLC_MNG_UPDATE_NOTIF,
		       iwl_fmac_tlc_update_notif, RX_HANDLER_SYNC),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_DISCONNECTED,
		       iwl_fmac_rx_disconnected, RX_HANDLER_ASYNC_LOCKED),
#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
	RX_HANDLER(DEBUG_LOG_MSG, iwl_fmac_rx_fw_logs, RX_HANDLER_SYNC),
#endif
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_SCAN_COMPLETE,
		       iwl_fmac_rx_scan_complete, RX_HANDLER_ASYNC_LOCKED),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_CONNECT_RESULT,
		       iwl_fmac_rx_connect_result, RX_HANDLER_ASYNC_LOCKED),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_KEYS_UPDATE,
		       iwl_fmac_rx_keys_update, RX_HANDLER_ASYNC_LOCKED),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_REG_UPDATE,
		       iwl_fmac_rx_reg_update, RX_HANDLER_ASYNC_LOCKED),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_EAPOL, iwl_fmac_rx_eapol,
		       RX_HANDLER_ASYNC_LOCKED),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_SEND_FRAME, iwl_fmac_rx_send_frame,
		       RX_HANDLER_SYNC),
	RX_HANDLER_GRP(DEBUG_GROUP, MFU_ASSERT_DUMP_NTF,
		       iwl_fmac_mfu_assert_dump_notif, RX_HANDLER_SYNC),
#ifdef CONFIG_THERMAL
	RX_HANDLER_GRP(PHY_OPS_GROUP, DTS_MEASUREMENT_NOTIF_WIDE,
		       iwl_fmac_temp_notif, RX_HANDLER_ASYNC_LOCKED),
#endif
	RX_HANDLER_GRP(PHY_OPS_GROUP, CT_KILL_NOTIFICATION,
		       iwl_fmac_ct_kill_notif, RX_HANDLER_SYNC),
#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
	RX_HANDLER_GRP(DEBUG_GROUP, DEBUG_HOST_NTF,
		       iwl_fmac_rx_dhc, RX_HANDLER_SYNC),
#endif /* CPTCFG_IWLWIFI_DHC_PRIVATE */
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_EXTERNAL_AUTH_REQUEST,
		       iwl_fmac_external_auth_request,
		       RX_HANDLER_ASYNC_LOCKED),
	RX_HANDLER_GRP(FMAC_GROUP, FMAC_EXTERNAL_AUTH_RX_MGMT,
		       iwl_fmac_external_auth_rx_mgmt, RX_HANDLER_SYNC)
};

#undef RX_HANDLER
#undef RX_HANDLER_GRP

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search
 */
static const struct iwl_hcmd_names iwl_fmac_legacy_names[] = {
	HCMD_NAME(UCODE_ALIVE_NTFY),
	HCMD_NAME(ECHO_CMD),
	HCMD_NAME(INIT_COMPLETE_NOTIF),
	HCMD_NAME(TX_CMD),
	HCMD_NAME(SCD_QUEUE_CFG),
	HCMD_NAME(TXPATH_FLUSH),
	HCMD_NAME(FW_PAGING_BLOCK_CMD),
	HCMD_NAME(PHY_CONFIGURATION_CMD),
	HCMD_NAME(CALIB_RES_NOTIF_PHY_DB),
	HCMD_NAME(PHY_DB_CMD),
	HCMD_NAME(NVM_ACCESS_CMD),
	HCMD_NAME(STATISTICS_NOTIFICATION),
	HCMD_NAME(MFUART_LOAD_NOTIFICATION),
	HCMD_NAME(REPLY_RX_MPDU_CMD),
	HCMD_NAME(FRAME_RELEASE),
	HCMD_NAME(BA_NOTIF),
	HCMD_NAME(DEBUG_HOST_COMMAND),
	HCMD_NAME(LDBG_CONFIG_CMD),
	HCMD_NAME(DEBUG_LOG_MSG),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search
 */
static const struct iwl_hcmd_names iwl_fmac_system_names[] = {
	HCMD_NAME(SHARED_MEM_CFG_CMD),
	HCMD_NAME(INIT_EXTENDED_CFG_CMD),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search
 */
static const struct iwl_hcmd_names iwl_fmac_phy_ops_names[] = {
	HCMD_NAME(CTDP_CONFIG_CMD),
	HCMD_NAME(CT_KILL_NOTIFICATION),
	HCMD_NAME(DTS_MEASUREMENT_NOTIF_WIDE),
};

static const struct iwl_hcmd_names iwl_fmac_datapath_names[] = {
	HCMD_NAME(TLC_MNG_UPDATE_NOTIF),
	HCMD_NAME(RX_QUEUES_NOTIFICATION),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search
 */
static const struct iwl_hcmd_names iwl_fmac_regulatory_and_nvm_names[] = {
	HCMD_NAME(NVM_ACCESS_COMPLETE),
	HCMD_NAME(NVM_GET_INFO),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search
 */
static const struct iwl_hcmd_names iwl_fmac_debug_names[] = {
	HCMD_NAME(DBGC_SUSPEND_RESUME),
	HCMD_NAME(BUFFER_ALLOCATION),
#ifdef CPTCFG_IWLWIFI_DHC_PRIVATE
	HCMD_NAME(DEBUG_HOST_NTF),
#endif /* CPTCFG_IWLWIFI_DHC_PRIVATE */
	HCMD_NAME(MFU_ASSERT_DUMP_NTF),
};

/* Please keep this array *SORTED* by hex value.
 * Access is done through binary search
 */
static const struct iwl_hcmd_names iwl_fmac_mlme_names[] = {
	HCMD_NAME(FMAC_SCAN),
	HCMD_NAME(FMAC_SCAN_ABORT),
	HCMD_NAME(FMAC_ADD_VIF),
	HCMD_NAME(FMAC_DEL_VIF),
	HCMD_NAME(FMAC_CONNECT),
	HCMD_NAME(FMAC_DISCONNECT),
	HCMD_NAME(FMAC_SAR),
	HCMD_NAME(FMAC_NVM),
	HCMD_NAME(FMAC_REQ_QUEUE),
	HCMD_NAME(FMAC_REL_QUEUE),
	HCMD_NAME(FMAC_SCD_QUEUE_CFG),
	HCMD_NAME(FMAC_CONFIG),
	HCMD_NAME(FMAC_REG_CFG),
	HCMD_NAME(FMAC_SET_PMK),
	HCMD_NAME(FMAC_ACK_STA_REMOVED),
	HCMD_NAME(FMAC_TEST_FIPS),
	HCMD_NAME(FMAC_MIC_FAILURE),
	HCMD_NAME(FMAC_TEMPORAL_KEY),
	HCMD_NAME(FMAC_EXTERNAL_AUTH_STATUS),

	/* notifications */
	HCMD_NAME(FMAC_EXTERNAL_AUTH_REQUEST),
	HCMD_NAME(FMAC_EXTERNAL_AUTH_RX_MGMT),
	HCMD_NAME(FMAC_SEND_FRAME),
	HCMD_NAME(FMAC_EAPOL),
	HCMD_NAME(FMAC_REG_UPDATE),
	HCMD_NAME(FMAC_KEYS_UPDATE),
	HCMD_NAME(FMAC_DISCONNECTED),
	HCMD_NAME(FMAC_DEBUG),
	HCMD_NAME(FMAC_CONNECT_RESULT),
	HCMD_NAME(FMAC_SCAN_COMPLETE),
};

static const struct iwl_hcmd_arr iwl_fmac_groups[] = {
	[LEGACY_GROUP] = HCMD_ARR(iwl_fmac_legacy_names),
	[LONG_GROUP] = HCMD_ARR(iwl_fmac_legacy_names),
	[SYSTEM_GROUP] = HCMD_ARR(iwl_fmac_system_names),
	[PHY_OPS_GROUP] = HCMD_ARR(iwl_fmac_phy_ops_names),
	[DATA_PATH_GROUP] = HCMD_ARR(iwl_fmac_datapath_names),
	[REGULATORY_AND_NVM_GROUP] =
		HCMD_ARR(iwl_fmac_regulatory_and_nvm_names),
	[FMAC_GROUP] = HCMD_ARR(iwl_fmac_mlme_names),
	[DEBUG_GROUP] = HCMD_ARR(iwl_fmac_debug_names),
};

static int iwl_fmac_fwrt_dump_start(void *ctx)
{
	struct iwl_fmac *fmac = ctx;

	mutex_lock(&fmac->mutex);

	return 0;
}

static void iwl_fmac_fwrt_dump_end(void *ctx)
{
	struct iwl_fmac *fmac = ctx;

	mutex_unlock(&fmac->mutex);
}

static int iwl_fmac_fwrt_send_hcmd(void *ctx, struct iwl_host_cmd *host_cmd)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)ctx;
	int ret;

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd(fmac, host_cmd);
	mutex_unlock(&fmac->mutex);

	return ret;
}

static const struct iwl_fw_runtime_ops iwl_fmac_fwrt_ops = {
	.dump_start = iwl_fmac_fwrt_dump_start,
	.dump_end = iwl_fmac_fwrt_dump_end,
	.send_hcmd = iwl_fmac_fwrt_send_hcmd,
};

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
static int iwl_fmac_tm_send_hcmd(void *op_mode, struct iwl_host_cmd *host_cmd)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)op_mode;

	if (WARN_ON_ONCE(!op_mode))
		return -EINVAL;

	return iwl_fmac_send_cmd(fmac, host_cmd);
}
#endif

static const struct ieee80211_txrx_stypes
iwl_fmac_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = {
		.tx = BIT(IEEE80211_STYPE_AUTH >> 4),
		.rx = BIT(IEEE80211_STYPE_AUTH >> 4),
	},
};

static struct iwl_op_mode *
iwl_op_mode_fmac_start(struct iwl_trans *trans, const struct iwl_cfg *cfg,
		       const struct iwl_fw *fw, struct dentry *dbgfs_dir)
{
	struct wiphy *wiphy;
	struct iwl_op_mode *op_mode;
	struct iwl_fmac *fmac;
	struct net_device *dev;
	struct iwl_trans_config trans_cfg = {};
	static const u8 no_reclaim_cmds[] = {
		TX_CMD,
	};
	int err, baid, i;
	const struct cfg80211_ops *cfg_ops = &iwl_fmac_cfg_ops;

	if (WARN(fw->ucode_capa.fmac_api_version < FMAC_MIN_API_VERSION ||
		 fw->ucode_capa.fmac_api_version > FMAC_MAX_API_VERSION,
		 "Unsupported FMAC API version: %d (min=%d, max=%d)",
		 fw->ucode_capa.fmac_api_version, FMAC_MIN_API_VERSION,
		 FMAC_MAX_API_VERSION))
		return NULL;

	if (WARN_ON(ARRAY_SIZE(fmac->queue_sta_map) <
	    trans->trans_cfg->base_params->num_of_queues))
		return NULL;

	wiphy = wiphy_new(cfg_ops,
			  sizeof(struct iwl_op_mode) + sizeof(struct iwl_fmac));
	if (!wiphy)
		return NULL;

	wiphy->mgmt_stypes = iwl_fmac_mgmt_stypes;

	op_mode = (void *)wiphy->priv;
	fmac = iwl_fmac_from_wiphy(wiphy);

	fmac->dev = trans->dev;
	fmac->trans = trans;
	fmac->fw = fw;
	fmac->cfg = cfg;

	iwl_fw_runtime_init(&fmac->fwrt, trans, fw, &iwl_fmac_fwrt_ops,
			    fmac, NULL, NULL, dbgfs_dir);

#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	fmac->internal_cmd_to_host = trans->dbg_cfg.intcmd_dbg;
#endif

	memset(fmac->queue_sta_map, IWL_FMAC_INVALID_STA_ID,
	       sizeof(fmac->queue_sta_map));

	for (baid = 0; baid < IWL_MAX_BAID; baid++) {
		int q;

		fmac->reorder_bufs[baid] =
			kcalloc(trans->num_rx_queues,
				sizeof(*fmac->reorder_bufs[baid]),
				GFP_KERNEL);
		if (!fmac->reorder_bufs[baid])
			goto out_free;

		for (q = 0; q < trans->num_rx_queues; q++) {
			fmac->reorder_bufs[baid][q].fmac = fmac;
			fmac->reorder_bufs[baid][q].sta_id =
				IWL_FMAC_INVALID_STA_ID;
		}
	}

	if (iwl_fmac_has_unified_ucode(fmac))
		iwl_fw_set_current_image(&fmac->fwrt, IWL_UCODE_REGULAR);
	else
		iwl_fw_set_current_image(&fmac->fwrt, IWL_UCODE_INIT);
	mutex_init(&fmac->mutex);

	op_mode->ops = &iwl_fmac_ops;

	trans->rx_mpdu_cmd_hdr_size =
		(trans->trans_cfg->device_family >= IWL_DEVICE_FAMILY_AX210) ?
		sizeof(struct iwl_rx_mpdu_desc) :
		IWL_RX_DESC_SIZE_V1;

	spin_lock_init(&fmac->async_handlers_lock);
	INIT_LIST_HEAD(&fmac->async_handlers_list);
	INIT_WORK(&fmac->async_handlers_wk, iwl_fmac_async_handlers_wk);
	INIT_WORK(&fmac->add_stream_wk, iwl_fmac_add_new_stream_wk);
	INIT_WORK(&fmac->restart_wk, iwl_fmac_nic_restart_wk);
	for (i = 0; i < ARRAY_SIZE(fmac->netdev_q_stop); i++)
		atomic_set(&fmac->netdev_q_stop[i], 0);

	/* configure transport layer */
	trans_cfg.op_mode = op_mode;
	trans_cfg.no_reclaim_cmds = no_reclaim_cmds;
	trans_cfg.n_no_reclaim_cmds = ARRAY_SIZE(no_reclaim_cmds);
	switch (iwlwifi_mod_params.amsdu_size) {
	case IWL_AMSDU_DEF:
	case IWL_AMSDU_4K:
		trans_cfg.rx_buf_size = IWL_AMSDU_4K;
		break;
	case IWL_AMSDU_8K:
		trans_cfg.rx_buf_size = IWL_AMSDU_8K;
		break;
	case IWL_AMSDU_12K:
		trans_cfg.rx_buf_size = IWL_AMSDU_12K;
		break;
	default:
		pr_err("%s: Unsupported amsdu_size: %d\n", KBUILD_MODNAME,
		       iwlwifi_mod_params.amsdu_size);
		trans_cfg.rx_buf_size = IWL_AMSDU_4K;
	}

	/* the hardware splits the A-MSDU */
	if (fmac->trans->trans_cfg->mq_rx_supported)
		trans_cfg.rx_buf_size = IWL_AMSDU_4K;

	trans->wide_cmd_header = true;
	trans_cfg.bc_table_dword =
		fmac->trans->trans_cfg->device_family < IWL_DEVICE_FAMILY_AX210;

	trans_cfg.command_groups = iwl_fmac_groups;
	trans_cfg.command_groups_size = ARRAY_SIZE(iwl_fmac_groups);

	trans_cfg.cmd_queue = 0;
	trans_cfg.cmd_fifo = IWL_FMAC_TX_FIFO_CMD;
	trans_cfg.scd_set_active = true;

	/* Set a short watchdog for the command queue */
	trans_cfg.cmd_q_wdg_timeout = IWL_DEF_WD_TIMEOUT;

	trans_cfg.cb_data_offs = offsetof(struct iwl_fmac_skb_info, trans);
	trans_cfg.fw_reset_handshake = fw_has_capa(&fmac->fw->ucode_capa,
						   IWL_UCODE_TLV_CAPA_FW_RESET_HANDSHAKE);

	iwl_trans_configure(fmac->trans, &trans_cfg);

	trans->rx_mpdu_cmd = REPLY_RX_MPDU_CMD;
	trans->dbg.dest_tlv = fmac->fw->dbg.dest_tlv;
	trans->dbg.n_dest_reg = fmac->fw->dbg.n_dest_reg;
	memcpy(trans->dbg.conf_tlv, fmac->fw->dbg.conf_tlv,
	       sizeof(trans->dbg.conf_tlv));
	trans->dbg.trigger_tlv = fmac->fw->dbg.trigger_tlv;

	trans->iml = fmac->fw->iml;
	trans->iml_len = fmac->fw->iml_len;

	snprintf(wiphy->fw_version, sizeof(wiphy->fw_version),
		 "%s", fw->fw_version);

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
	iwl_dnt_init(fmac->trans, dbgfs_dir);
	iwl_tm_init(trans, fmac->fw, &fmac->mutex, fmac);
#endif

	fmac->user_power_level = IWL_FMAC_POWER_LEVEL_UNSET;

	/* set up notification wait support */
	iwl_notification_wait_init(&fmac->notif_wait);
	fmac->phy_db = iwl_phy_db_init(trans);
	if (!fmac->phy_db) {
		IWL_ERR(fmac, "Cannot init phy_db\n");
		goto out_free;
	}

	IWL_INFO(fmac, "Detected %s, REV=0x%X\n",
		 fmac->trans->name, fmac->trans->hw_rev);

	if (iwlwifi_mod_params.nvm_file)
		fmac->nvm_file_name = iwlwifi_mod_params.nvm_file;
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	else if (trans->dbg_cfg.nvm_file)
		fmac->nvm_file_name = trans->dbg_cfg.nvm_file;
#endif
	else
		IWL_DEBUG_EEPROM(fmac->trans->dev,
				 "working without external nvm file\n");

	err = iwl_trans_start_hw(trans);
	if (err)
		goto out_free;

	mutex_lock(&fmac->mutex);
	err = iwl_fmac_run_init_fw(fmac);
	if (err) {
		if (err != -ERFKILL)
			iwl_fw_dbg_error_collect(&fmac->fwrt,
						 FW_DBG_TRIGGER_DRIVER);
		IWL_ERR(fmac, "Failed to run INIT ucode: %d\n", err);
		mutex_unlock(&fmac->mutex);
		goto stop_device;
	}
	mutex_unlock(&fmac->mutex);

	iwl_fw_dbg_stop_sync(&fmac->fwrt);
	iwl_trans_stop_device(fmac->trans);

	iwl_fmac_setup_wiphy(fmac);

	err = wiphy_register(wiphy);
	if (err) {
		IWL_ERR(fmac, "Failed to register wiphy: %d\n", err);
		goto stop_device;
	}

	rtnl_lock();
	dev = iwl_fmac_create_netdev(fmac, "wlan%d", NET_NAME_ENUM,
				     NL80211_IFTYPE_STATION, NULL);
	rtnl_unlock();
	if (IS_ERR_OR_NULL(dev))
		IWL_ERR(fmac, "failed to create default netdev\n");

	iwl_fmac_dbgfs_init(fmac, dbgfs_dir);

	iwl_fmac_thermal_initialize(fmac);

	return op_mode;

stop_device:
	if (!iwlfmac_mod_params.init_dbg) {
		iwl_fw_dbg_stop_sync(&fmac->fwrt);
		iwl_trans_stop_device(fmac->trans);
	}
out_free:
	iwl_phy_db_free(fmac->phy_db);
	iwl_fw_flush_dumps(&fmac->fwrt);
	for (baid = 0; baid < IWL_MAX_BAID; baid++)
		kfree(fmac->reorder_bufs[baid]);
	iwl_fw_runtime_free(&fmac->fwrt);
	wiphy_free(wiphy);
	return NULL;
}

struct iwl_async_handler_entry {
	struct list_head list;
	struct iwl_rx_cmd_buffer rxb;
	void (*fn)(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb);
};

static void iwl_fmac_async_handlers_purge(struct iwl_fmac *fmac)
{
	struct iwl_async_handler_entry *entry, *tmp;

	spin_lock_bh(&fmac->async_handlers_lock);
	list_for_each_entry_safe(entry, tmp, &fmac->async_handlers_list, list) {
		iwl_free_rxb(&entry->rxb);
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock_bh(&fmac->async_handlers_lock);
}

void iwl_fmac_process_async_handlers(struct iwl_fmac *fmac)
{
	struct iwl_async_handler_entry *entry, *tmp;
	LIST_HEAD(local_list);

	lockdep_assert_held(&fmac->mutex);

	/* Ensure that we are not in stop flow (check iwl_fmac_mac_stop) */

	/*
	 * Sync with Rx path with a lock. Remove all the entries from this list,
	 * add them to a local one (lock free), and then handle them.
	 */
	spin_lock_bh(&fmac->async_handlers_lock);
	list_splice_init(&fmac->async_handlers_list, &local_list);
	spin_unlock_bh(&fmac->async_handlers_lock);

	list_for_each_entry_safe(entry, tmp, &local_list, list) {
		entry->fn(fmac, &entry->rxb);
		iwl_free_rxb(&entry->rxb);
		list_del(&entry->list);
		kfree(entry);
	}
}

static void iwl_fmac_async_handlers_wk(struct work_struct *wk)
{
	struct iwl_fmac *fmac =
		container_of(wk, struct iwl_fmac, async_handlers_wk);

	mutex_lock(&fmac->mutex);
	iwl_fmac_process_async_handlers(fmac);
	mutex_unlock(&fmac->mutex);
}

static void iwl_fmac_rx_check_trigger(struct iwl_fmac *fmac,
				      struct iwl_rx_packet *pkt)
{
	struct iwl_fw_dbg_trigger_tlv *trig;
	struct iwl_fw_dbg_trigger_cmd *cmds_trig;
	int i;

	trig = iwl_fw_dbg_trigger_on(&fmac->fwrt, NULL,
				     FW_DBG_TRIGGER_FW_NOTIF);
	if (!trig)
		return;

	cmds_trig = (void *)trig->data;

	for (i = 0; i < ARRAY_SIZE(cmds_trig->cmds); i++) {
		if (cmds_trig->cmds[i].cmd_id != pkt->hdr.cmd ||
		    cmds_trig->cmds[i].group_id != pkt->hdr.group_id)
			continue;

		iwl_fw_dbg_collect_trig(&fmac->fwrt, trig,
					"CMD 0x%02x.%02x received",
					pkt->hdr.group_id, pkt->hdr.cmd);
		break;
	}
}

static void iwl_fmac_rx_notification(struct iwl_fmac *fmac,
				     struct iwl_rx_cmd_buffer *rxb,
				     struct iwl_rx_packet *pkt)
{
	int i, notif_triggered;
	union iwl_dbg_tlv_tp_data tp_data = { .fw_pkt = pkt };

	iwl_dbg_tlv_time_point(&fmac->fwrt,
			       IWL_FW_INI_TIME_POINT_FW_RSP_OR_NOTIF, &tp_data);
	iwl_fmac_rx_check_trigger(fmac, pkt);

	/*
	 * Do the notification wait before RX handlers so
	 * even if the RX handler consumes the RXB we have
	 * access to it in the notification wait entry.
	 * But don't wake up the waiter until we have added
	 * the ASYNC handler to fmac->async_handlers_list.
	 */
	notif_triggered = iwl_notification_wait(&fmac->notif_wait, pkt);

	for (i = 0; i < ARRAY_SIZE(iwl_fmac_rx_handlers); i++) {
		const struct iwl_rx_handlers *rx_h = &iwl_fmac_rx_handlers[i];
		struct iwl_async_handler_entry *entry;

		if (rx_h->cmd_id != WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd))
			continue;

		if (rx_h->context == RX_HANDLER_SYNC) {
			rx_h->fn(fmac, rxb);
			goto wake_waiter;
		}

		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		/* we can't do much... */
		if (!entry)
			goto wake_waiter;

		entry->rxb._page = rxb_steal_page(rxb);
		entry->rxb._offset = rxb->_offset;
		entry->rxb._rx_page_order = rxb->_rx_page_order;
		entry->fn = rx_h->fn;
		spin_lock(&fmac->async_handlers_lock);
		list_add_tail(&entry->list, &fmac->async_handlers_list);
		spin_unlock(&fmac->async_handlers_lock);
		schedule_work(&fmac->async_handlers_wk);
		goto wake_waiter;
	}

wake_waiter:
	if (notif_triggered)
		iwl_notification_notify(&fmac->notif_wait);
}

static void iwl_fmac_rx_queue_sync(struct iwl_fmac *fmac,
				   struct iwl_rx_packet *pkt,
				   int queue)
{
	struct iwl_rxq_sync_notification *notif = (void *)pkt->data;
	struct iwl_rxq_sync_payload *payload = (void *)notif->payload;

	/* not used yet */
	if (payload->src != IWL_FMAC_SYNC_SRC_FMAC)
		return;

	switch (payload->type) {
	case IWL_FMAC_SYNC_TYPE_DELBA:
		iwl_fmac_rx_delba_ntfy(fmac, pkt, queue);
		break;
	}
}

static void iwl_fmac_rx(struct iwl_op_mode *op_mode,
			struct napi_struct *napi,
			struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	u16 cmd = WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd);

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
	/*
	 * RX data may be forwarded to userspace in case the user
	 * requested to monitor the rx w/o affecting the regular flow.
	 * In this case the iwl_test object will handle forwarding the rx
	 * data to user space.
	 */
	iwl_tm_gnl_send_rx(fmac->trans, rxb);
#endif

	if (likely(cmd == WIDE_ID(LEGACY_GROUP, REPLY_RX_MPDU_CMD)))
		iwl_fmac_rx_mpdu(fmac, napi, rxb, 0);
	else if (cmd == WIDE_ID(LEGACY_GROUP, FRAME_RELEASE))
		iwl_fmac_rx_frame_release(fmac, napi, pkt, 0);
	else if (cmd == WIDE_ID(DATA_PATH_GROUP, RX_QUEUES_NOTIFICATION))
		iwl_fmac_rx_queue_sync(fmac, pkt, 0);
	else
		iwl_fmac_rx_notification(fmac, rxb, pkt);
}

static void iwl_fmac_rx_rss(struct iwl_op_mode *op_mode,
			    struct napi_struct *napi,
			    struct iwl_rx_cmd_buffer *rxb,
			    unsigned int queue)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	u16 cmd = WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd);

	if (likely(cmd == WIDE_ID(LEGACY_GROUP, REPLY_RX_MPDU_CMD)))
		iwl_fmac_rx_mpdu(fmac, napi, rxb, queue);
	else if (cmd == WIDE_ID(LEGACY_GROUP, FRAME_RELEASE))
		iwl_fmac_rx_frame_release(fmac, napi, pkt, queue);
	else if (cmd == WIDE_ID(DATA_PATH_GROUP, RX_QUEUES_NOTIFICATION))
		iwl_fmac_rx_queue_sync(fmac, pkt, queue);
}

static bool iwl_fmac_set_hw_rfkill_state(struct iwl_op_mode *op_mode,
					 bool state)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	bool rfkill_safe_init_done = READ_ONCE(fmac->rfkill_safe_init_done);
	bool unified = iwl_fmac_has_unified_ucode(fmac);

	if (state)
		set_bit(IWL_STATUS_HW_RFKILL, &fmac->status);
	else
		clear_bit(IWL_STATUS_HW_RFKILL, &fmac->status);

	wiphy_rfkill_set_hw_state(wiphy_from_fmac(fmac), state);

	 /* _iwl_fmac_run_init_fw is waiting for results, abort it */
	if (rfkill_safe_init_done)
		iwl_abort_notification_waits(&fmac->notif_wait);

	/*
	 * Don't ask the transport to stop the firmware. We'll do it
	 * after cfg80211 takes us down.
	 */
	if (unified)
		return false;

	return state && rfkill_safe_init_done;
}

static void iwl_fmac_free_skb(struct iwl_op_mode *op_mode, struct sk_buff *skb)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	struct iwl_fmac_skb_info *info = (void *)skb->cb;

	iwl_trans_free_tx_cmd(fmac->trans, info->dev_cmd);
	dev_kfree_skb_any(skb);
}

static void iwl_fmac_nic_error(struct iwl_op_mode *op_mode, bool sync)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct wireless_dev *wdev;

	/* Close the data path immediately and clean up later */
	rcu_read_lock();
	list_for_each_entry_rcu(wdev, &wiphy->wdev_list, list) {
		if (wdev->netdev)
			netif_tx_stop_all_queues(wdev->netdev);
	}
	rcu_read_unlock();

	iwl_fmac_dump_nic_error_log(fmac);

	iwl_fw_error_collect(&fmac->fwrt, sync);

	schedule_work(&fmac->restart_wk);
}

static void iwl_fmac_cmd_queue_full(struct iwl_op_mode *op_mode)
{
	WARN_ON(1);
}

void iwl_fmac_stop_ac_queue(struct iwl_fmac *fmac, struct wireless_dev *wdev,
			    int ac)
{
	if (atomic_inc_return(&fmac->netdev_q_stop[ac]) > 1) {
		IWL_DEBUG_TX_QUEUES(fmac,
				    "netdev queue %d already stopped\n", ac);
		return;
	}

	netif_stop_subqueue(wdev->netdev, ac);
}

void iwl_fmac_wake_ac_queue(struct iwl_fmac *fmac, struct wireless_dev *wdev,
			    int ac)
{
	if (atomic_dec_return(&fmac->netdev_q_stop[ac]) > 0) {
		IWL_DEBUG_TX_QUEUES(fmac,
				    "netdev queue %d still stopped\n", ac);
		return;
	}

	netif_wake_subqueue(wdev->netdev, ac);
}

static int iwl_fmac_get_ac_queue(struct iwl_fmac *fmac,
				 struct iwl_fmac_sta *sta, int queue)
{
	int i, ac = -1;

	for (i = 0; i < ARRAY_SIZE(sta->tids); i++) {
		u8 txq_id = sta->tids[i].txq_id;

		if (txq_id != queue)
			continue;

		ac = tid_to_ac[i];
		break;
	}

	return ac;
}

static void iwl_fmac_stop_sw_queue(struct iwl_op_mode *op_mode, int queue)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	u8 sta_id = fmac->queue_sta_map[queue];
	struct iwl_fmac_sta *sta;
	int ac;

	rcu_read_lock();

	sta = rcu_dereference(fmac->stas[sta_id]);
	if (IS_ERR_OR_NULL(sta))
		goto out;

	ac = iwl_fmac_get_ac_queue(fmac, sta, queue);
	if (ac != -1)
		iwl_fmac_stop_ac_queue(fmac, &sta->vif->wdev, ac);

out:
	rcu_read_unlock();

}

static void iwl_fmac_wake_sw_queue(struct iwl_op_mode *op_mode, int queue)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	u8 sta_id = fmac->queue_sta_map[queue];
	struct iwl_fmac_sta *sta;
	int ac;

	rcu_read_lock();

	sta = rcu_dereference(fmac->stas[sta_id]);
	if (IS_ERR_OR_NULL(sta))
		goto out;

	ac = iwl_fmac_get_ac_queue(fmac, sta, queue);
	if (ac != -1)
		iwl_fmac_wake_ac_queue(fmac, &sta->vif->wdev, ac);

out:
	rcu_read_unlock();

}

static void iwl_op_mode_fmac_stop(struct iwl_op_mode *op_mode)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct wireless_dev *wdev, *tmp;
	int baid;

	cancel_work_sync(&fmac->async_handlers_wk);
	iwl_fmac_async_handlers_purge(fmac);
	cancel_work_sync(&fmac->restart_wk);
	flush_work(&fmac->add_stream_wk);

	iwl_fmac_dbgfs_exit(fmac);

	rtnl_lock();
	fmac->shutdown = true;
	cfg80211_shutdown_all_interfaces(wiphy);
	wiphy_lock(wiphy);
	list_for_each_entry_safe(wdev, tmp, &wiphy->wdev_list, list)
		iwl_fmac_destroy_vif(vif_from_wdev(wdev));
	wiphy_unlock(wiphy);
	rtnl_unlock();

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
	iwl_dnt_free(fmac->trans);
#endif

	iwl_fmac_thermal_exit(fmac);

	iwl_trans_op_mode_leave(fmac->trans);

	wiphy_unregister(wiphy);
	mutex_destroy(&fmac->mutex);

	iwl_phy_db_free(fmac->phy_db);
	fmac->phy_db = NULL;

	for (baid = 0; baid < IWL_MAX_BAID; baid++)
		kfree(fmac->reorder_bufs[baid]);
	iwl_fw_runtime_free(&fmac->fwrt);
	wiphy_free(wiphy_from_fmac(fmac));
}

static int iwl_fmac_alloc_queue_old(struct iwl_fmac *fmac,
				    struct iwl_fmac_sta *sta,
				    u8 tid, struct ieee80211_hdr *hdr)
{
	struct iwl_fmac_req_queue cmd = {
		.vif_id = sta->vif->id,
		.sta_id = sta->sta_id,
		.tid = tid,
	};
	struct iwl_fmac_req_queue_response *resp;
	struct iwl_host_cmd hcmd = {
		.id = WIDE_ID(FMAC_GROUP, FMAC_REQ_QUEUE),
		.flags = CMD_WANT_SKB,
		.data = { &cmd, },
		.len = { sizeof(cmd), },
	};
	struct iwl_fmac_txq_scd_cfg cfg = {
		.vif_id = sta->vif->id,
		.fifo = iwl_fmac_tid_to_tx_fifo[tid],
		.sta_id = sta->sta_id,
		.tid = tid,
		.frame_limit = IWL_FRAME_LIMIT,
	};
	u8 queue;
	u16 ssn;
	int ret;

	lockdep_assert_held(&fmac->mutex);

	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	if (ret)
		return ret;

	resp = (void *)((struct iwl_rx_packet *)hcmd.resp_pkt)->data;
	queue = resp->queue;

	/* Make sure a queue was allocated */
	if (queue == IWL_FMAC_NO_QUEUE) {
		ret = -ENOSR;
		goto out;
	}

	/* Make sure this TXQ wasn't already allocated to someone */
	if (WARN_ON(fmac->queue_sta_map[queue] != IWL_FMAC_INVALID_STA_ID)) {
		IWL_ERR(fmac, "Trying to enable TXQ %d that is in use\n",
			queue);
		ret = -EEXIST;
		goto out;
	}

	fmac->queue_sta_map[queue] = sta->sta_id;

	ssn = IEEE80211_SEQ_TO_SN(le16_to_cpu(hdr->seq_ctrl));

	/* TODO: set timeout without hardcoding the value */
	iwl_fmac_enable_txq(fmac, queue, ssn, &cfg, 10000);

	IWL_DEBUG_TX_QUEUES(fmac, "Allocating queue #%d to sta %d on tid %d\n",
			    queue, sta->sta_id, tid);

	ret = 0;

out:
	iwl_free_resp(&hcmd);
	return ret;
}

int iwl_fmac_alloc_queue(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			 u8 tid, struct ieee80211_hdr *hdr)
{
	int queue, size = max_t(u32, IWL_DEFAULT_QUEUE_SIZE,
				fmac->trans->cfg->min_ba_txq_size);

	if (!iwl_fmac_has_new_tx_api(fmac))
		return iwl_fmac_alloc_queue_old(fmac, sta, tid, hdr);

	queue = iwl_trans_txq_alloc(fmac->trans,
				    cpu_to_le16(TX_QUEUE_CFG_ENABLE_QUEUE),
				    sta->sta_id, tid, SCD_QUEUE_CFG, size, 0);
	if (queue < 0) {
		IWL_DEBUG_TX_QUEUES(fmac,
				    "Failed allocating TXQ for sta %d tid %d, ret: %d\n",
				    sta->sta_id, tid, queue);
		return queue;
	}

	IWL_DEBUG_TX_QUEUES(fmac, "Allocated TXQ #%d for sta %d tid %d\n",
			    queue, sta->sta_id, tid);

	fmac->queue_sta_map[queue] = sta->sta_id;
	sta->tids[tid].txq_id = queue;

	return 0;
}

static void iwl_fmac_release_txq_old(struct iwl_fmac *fmac,
				     struct iwl_fmac_sta *sta,
				     int queue, u8 tid)
{
	struct iwl_fmac_rel_queue rel_queue_cmd = {
		.tid = tid,
	};
	struct iwl_fmac_rel_queue_response *rel_queue_resp;
	struct iwl_host_cmd rel_queue_hcmd = {
		.id = WIDE_ID(FMAC_GROUP, FMAC_REL_QUEUE),
		.flags = CMD_WANT_SKB,
		.data = { &rel_queue_cmd, },
		.len = { sizeof(rel_queue_cmd), },
	};
	u8 sta_id;
	int ret;

	lockdep_assert_held(&fmac->mutex);

	sta_id = fmac->queue_sta_map[queue];
	if (WARN(sta_id == IWL_FMAC_INVALID_STA_ID,
		 "invalid STA for queue %d\n", queue))
		return;

	if (WARN_ON(sta->sta_id != sta_id))
		return;

	sta->tids[tid].txq_id = IWL_FMAC_INVALID_TXQ_ID;
	fmac->queue_sta_map[queue] = IWL_FMAC_INVALID_STA_ID;

	rel_queue_cmd.vif_id = sta->vif->id;
	rel_queue_cmd.sta_id = sta->sta_id;

	ret = iwl_fmac_send_cmd(fmac, &rel_queue_hcmd);
	if (ret)
		return;

	/* Make sure we need to actually free the queue */
	rel_queue_resp =
		(void *)((struct iwl_rx_packet *)rel_queue_hcmd.resp_pkt)->data;
	if (!rel_queue_resp->free_queue) {
		IWL_DEBUG_TX_QUEUES(fmac, "Freed TID %d on TXQ #%d\n", tid,
				    queue);
		goto out;
	}

	iwl_fmac_disable_txq(fmac, sta, queue);

out:
	iwl_free_resp(&rel_queue_hcmd);
}

void iwl_fmac_release_txq(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			  int queue, u8 tid)
{
	if (!iwl_fmac_has_new_tx_api(fmac))
		return iwl_fmac_release_txq_old(fmac, sta, queue, tid);
	iwl_fmac_disable_txq(fmac, sta, queue);
}

static void iwl_op_mode_fmac_time_point(struct iwl_op_mode *op_mode,
					enum iwl_fw_ini_time_point tp_id,
					union iwl_dbg_tlv_tp_data *tp_data)
{
	struct iwl_fmac *fmac = iwl_fmac_from_opmode(op_mode);

	iwl_dbg_tlv_time_point(&fmac->fwrt, tp_id, tp_data);
}

#define IWL_FMAC_COMMON_OPS					\
	.queue_full = iwl_fmac_stop_sw_queue,			\
	.queue_not_full = iwl_fmac_wake_sw_queue,		\
	.hw_rf_kill = iwl_fmac_set_hw_rfkill_state,		\
	.free_skb = iwl_fmac_free_skb,				\
	.nic_error = iwl_fmac_nic_error,			\
	.cmd_queue_full = iwl_fmac_cmd_queue_full,		\
	.nic_config = iwl_fmac_nic_config,			\
	/* as we only register one, these MUST be common! */	\
	.start = iwl_op_mode_fmac_start,			\
	.stop = iwl_op_mode_fmac_stop,				\
	.rx = iwl_fmac_rx,					\
	.rx_rss = iwl_fmac_rx_rss,				\
	.time_point = iwl_op_mode_fmac_time_point

static const struct iwl_op_mode_ops iwl_fmac_ops = {
	IWL_FMAC_COMMON_OPS,
#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
	.test_ops = {
		.send_hcmd = iwl_fmac_tm_send_hcmd,
	},
#endif
};


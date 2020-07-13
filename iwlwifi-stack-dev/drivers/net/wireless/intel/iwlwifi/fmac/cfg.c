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
#include <linux/etherdevice.h>
#include <net/cfg80211.h>

#include "iwl-nvm-parse.h"

#include "fmac.h"

static struct wireless_dev *
iwl_fmac_cfg_add_virtual_intf(struct wiphy *wiphy, const char *name,
			      unsigned char name_assign_type,
			      enum nl80211_iftype type,
			      struct vif_params *params)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct net_device *dev;

	if (fmac->shutdown)
		return ERR_PTR(-ESHUTDOWN);

	dev = iwl_fmac_create_netdev(fmac, name, name_assign_type,
				     type, params);
	if (IS_ERR(dev))
		return ERR_PTR(PTR_ERR(dev));

	return &vif_from_netdev(dev)->wdev;
}

static int iwl_fmac_cfg_del_virtual_intf(struct wiphy *wiphy,
					 struct wireless_dev *wdev)
{
	iwl_fmac_destroy_vif(vif_from_wdev(wdev));
	return 0;
}

static int iwl_fmac_cfg_change_virtual_intf(struct wiphy *wiphy,
					    struct net_device *dev,
					    enum nl80211_iftype type,
					    struct vif_params *params)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);

	if (vif->wdev.iftype != type) {
		if (vif->id != FMAC_VIF_ID_INVALID)
			/* This is ok - cfg80211 will reopen this vif */
			return -EBUSY;
		vif->wdev.iftype = type;
		memset(&vif->u, 0, sizeof(vif->u));
	}

	return 0;
}

static int scan_cfg(struct cfg80211_scan_request *request,
		    struct iwl_fmac_scan_cmd *cmd, unsigned int cmd_size)
{
	int i;

	if (WARN_ON(request->n_channels > IWL_FMAC_MAX_CHANS))
		return -EINVAL;

	cmd->vif_id = vif_from_wdev(request->wdev)->id;

	/* TODO: convert request->rates to cmd->rates bitmap */

	cmd->n_ssids = request->n_ssids;
	for (i = 0; i < request->n_ssids; i++) {
		memcpy(cmd->ssids[i], request->ssids[i].ssid,
		       request->ssids[i].ssid_len);
		cmd->ssids_lengths[i] = request->ssids[i].ssid_len;
	}

	for (i = 0; i < request->n_channels; i++)
		cmd->freqs[i] = cpu_to_le16(request->channels[i]->center_freq);
	cmd->n_freqs = request->n_channels;

	cmd->random_mac = !!(request->flags & NL80211_SCAN_FLAG_RANDOM_ADDR);
	ether_addr_copy(cmd->bssid, request->bssid);
	cmd->ie_len = cpu_to_le16(request->ie_len);
	memcpy(cmd->ie, request->ie, request->ie_len);

	return 0;
}

static int iwl_fmac_cfg_scan(struct wiphy *wiphy,
			     struct cfg80211_scan_request *request)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	unsigned int cmd_size;
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(FMAC_SCAN, FMAC_GROUP, 0),
		.dataflags = { IWL_HCMD_DFL_NOCOPY, },
	};
	void *ptr = NULL;
	int ret;

	mutex_lock(&fmac->mutex);

	if (WARN_ON(fmac->scan_request)) {
		ret = -EBUSY;
		goto out;
	}

	cmd_size = ALIGN(sizeof(struct iwl_fmac_scan_cmd) +
			 request->ie_len, 4);
	ptr = kmalloc(cmd_size, GFP_KERNEL);
	if (!ptr) {
		ret = -ENOMEM;
		goto out;
	}

	ret = scan_cfg(request, ptr, cmd_size);
	if (ret < 0)
		goto out;

	hcmd.data[0] = ptr;
	hcmd.len[0] = cmd_size;

	ret = iwl_fmac_send_cmd(fmac, &hcmd);

	if (ret == 0)
		fmac->scan_request = request;

 out:
	mutex_unlock(&fmac->mutex);
	kfree(ptr);

	return ret;
}

int iwl_fmac_abort_scan(struct iwl_fmac *fmac, struct iwl_fmac_vif *vif)
{
	struct iwl_notification_wait wait_scan_done;
	static const u16 scan_done_notif[] = {
		WIDE_ID(FMAC_GROUP, FMAC_SCAN_COMPLETE),
	};
	struct iwl_fmac_scan_abort_cmd cmd = {
		.vif_id = vif->id,
	};
	int ret;

	lockdep_assert_held(&fmac->mutex);

	if (iwl_fmac_is_radio_killed(fmac)) {
		struct cfg80211_scan_info info = {
			.aborted = true,
		};

		if (WARN_ON(!fmac->scan_request))
			return 0;

		IWL_DEBUG_SCAN(fmac, "Stop scan in RFKILL - skip command\n");
		cfg80211_scan_done(fmac->scan_request, &info);
		fmac->scan_request = NULL;
		return 0;
	}

	iwl_init_notification_wait(&fmac->notif_wait, &wait_scan_done,
				   scan_done_notif,
				   ARRAY_SIZE(scan_done_notif),
				   NULL, NULL);

	IWL_DEBUG_SCAN(fmac, "Preparing to stop scan\n");

	ret = iwl_fmac_send_cmd_pdu(fmac,
				    iwl_cmd_id(FMAC_SCAN_ABORT, FMAC_GROUP, 0),
				    0, sizeof(cmd), &cmd);
	if (ret) {
		IWL_DEBUG_SCAN(fmac, "couldn't stop scan\n");
		iwl_remove_notification(&fmac->notif_wait, &wait_scan_done);
		return ret;
	}

	ret = iwl_wait_notification(&fmac->notif_wait, &wait_scan_done,
				    HZ * CPTCFG_IWL_TIMEOUT_FACTOR);
	return ret;
}

static void iwl_fmac_cfg_abort_scan(struct wiphy *wiphy,
				    struct wireless_dev *wdev)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_wdev(wdev);

	mutex_lock(&fmac->mutex);
	iwl_fmac_abort_scan(fmac, vif);
	mutex_unlock(&fmac->mutex);
}

static u32 cipher_suites_to_fmac_ciphers(unsigned int n_suites, u32 *suites)
{
	int i;
	u32 suite;
	u32 ciphers = 0;

	for (i = 0; i < n_suites; i++) {
		suite = suites[i];

		if (suite == WLAN_CIPHER_SUITE_CCMP_256)
			ciphers |= IWL_FMAC_CIPHER_CCMP_256;
		if (suite == WLAN_CIPHER_SUITE_GCMP_256)
			ciphers |= IWL_FMAC_CIPHER_GCMP_256;
		if (suite == WLAN_CIPHER_SUITE_CCMP)
			ciphers |= IWL_FMAC_CIPHER_CCMP;
		if (suite == WLAN_CIPHER_SUITE_GCMP)
			ciphers |= IWL_FMAC_CIPHER_GCMP;
		if (suite == WLAN_CIPHER_SUITE_TKIP)
			ciphers |= IWL_FMAC_CIPHER_TKIP;
		if (suite == WLAN_CIPHER_SUITE_WEP104)
			ciphers |= IWL_FMAC_CIPHER_WEP104;
		if (suite == WLAN_CIPHER_SUITE_WEP40)
			ciphers |= IWL_FMAC_CIPHER_WEP40;
	}
	return ciphers ? : IWL_FMAC_CIPHER_NONE;
}

static int
cfg_crypto_to_iwlfmac_crypto(struct iwl_fmac *fmac,
			     struct cfg80211_crypto_settings *cfg_crypto,
			     struct iwl_fmac_crypto *iwl_crypto)
{
	u32 i, val;

	if (cfg_crypto->wep_keys) {
		for (i = 0; i < IWL_NUM_WEP_KEYS; i++) {
			if (cfg_crypto->wep_keys[i].cipher) {
				memcpy(iwl_crypto->u.wep.key[i],
				       cfg_crypto->wep_keys[i].key,
				       cfg_crypto->wep_keys[i].key_len);
				iwl_crypto->u.wep.key_len[i] =
					cfg_crypto->wep_keys[i].key_len;
			}
		}

		iwl_crypto->u.wep.def_key = cfg_crypto->wep_tx_key;
	} else {
		if (cfg_crypto->psk)
			memcpy(iwl_crypto->u.wpa.psk, cfg_crypto->psk,
			       WLAN_PMK_LEN);

		val = 0;
		if (cfg_crypto->wpa_versions & NL80211_WPA_VERSION_1)
			val |= IWL_FMAC_PROTO_WPA;
		if (cfg_crypto->wpa_versions & NL80211_WPA_VERSION_2)
			val |= IWL_FMAC_PROTO_RSN;
		iwl_crypto->u.wpa.proto = cpu_to_le32(val);
	}

	val = cipher_suites_to_fmac_ciphers(cfg_crypto->n_ciphers_group,
					    cfg_crypto->ciphers_group);
	iwl_crypto->cipher_group = cpu_to_le32(val);

	val = cipher_suites_to_fmac_ciphers(cfg_crypto->n_ciphers_pairwise,
					    cfg_crypto->ciphers_pairwise);
	iwl_crypto->ciphers_pairwise = cpu_to_le32(val);

	val = 0;
	for (i = 0; i < cfg_crypto->n_akm_suites; i++) {
		switch (cfg_crypto->akm_suites[i]) {
		case WLAN_AKM_SUITE_PSK:
			val |= IWL_FMAC_KEY_MGMT_PSK;
			break;
		case WLAN_AKM_SUITE_FT_PSK:
			val |= IWL_FMAC_KEY_MGMT_FT_PSK;
			break;
		case WLAN_AKM_SUITE_PSK_SHA256:
			val |= IWL_FMAC_KEY_MGMT_PSK_SHA256;
			break;
		case WLAN_AKM_SUITE_8021X:
			val |= IWL_FMAC_KEY_MGMT_IEEE8021X;
			break;
		case WLAN_AKM_SUITE_8021X_SHA256:
			val |= IWL_FMAC_KEY_MGMT_IEEE8021X_SHA256;
			break;
		case WLAN_AKM_SUITE_8021X_SUITE_B:
			val |= IWL_FMAC_KEY_MGMT_IEEE8021X_SUITE_B;
			break;
		case WLAN_AKM_SUITE_8021X_SUITE_B_192:
			val |= IWL_FMAC_KEY_MGMT_IEEE8021X_SUITE_B_192;
			break;
		case WLAN_AKM_SUITE_FT_8021X:
			val |= IWL_FMAC_KEY_MGMT_FT_IEEE8021X;
			break;
		case WLAN_AKM_SUITE_SAE:
			val |= IWL_FMAC_KEY_MGMT_SAE;
			break;
		default:
			IWL_ERR(fmac, "Unsupported akm_suite: 0x%x\n",
				cfg_crypto->akm_suites[i]);
			return -EINVAL;
		}
	}
	iwl_crypto->key_mgmt = cpu_to_le32(val);

	return 0;
}

static int iwl_fmac_cfg_connect(struct wiphy *wiphy, struct net_device *dev,
				struct cfg80211_connect_params *sme)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac_connect_cmd cmd = {
		.vif_id = vif->id,
	};
	int ret;

	if (vif->u.mgd.connect_state != IWL_FMAC_CONNECT_IDLE)
		return -EBUSY;

	vif->u.mgd.connect_state = IWL_FMAC_CONNECT_CONNECTING;

	if (sme->channel) {
		cmd.flags |= cpu_to_le32(IWL_FMAC_FREQ_IN_USE);
		cmd.center_freq = cpu_to_le16(sme->channel->center_freq);
	}

	if (sme->channel_hint) {
		cmd.flags |= cpu_to_le32(IWL_FMAC_FREQ_IN_USE |
					 IWL_FMAC_FREQ_HINT);
		cmd.center_freq = cpu_to_le16(sme->channel_hint->center_freq);
	}

	if (sme->bssid)
		memcpy(cmd.bssid, sme->bssid, ETH_ALEN);

	cmd.ssid_len = sme->ssid_len;
	memcpy(cmd.ssid, sme->ssid, sme->ssid_len);

	ret = cfg_crypto_to_iwlfmac_crypto(fmac, &sme->crypto, &cmd.crypto);
	if (ret)
		return ret;

	vif->control_port_ethertype = sme->crypto.control_port_ethertype;

	if (sme->mfp && !iwl_fmac_has_new_tx_api(fmac))
		return -EOPNOTSUPP;

	if (sme->mfp == NL80211_MFP_REQUIRED)
		cmd.crypto.mfp = IWL_FMAC_MFP_REQUIRED;

	if (sme->mfp == NL80211_MFP_OPTIONAL)
		cmd.crypto.mfp = IWL_FMAC_MFP_OPTIONAL;

	if (sme->flags & CONNECT_REQ_EXTERNAL_AUTH_SUPPORT)
		cmd.flags |=
			cpu_to_le32(IWL_FMAC_CONNECT_FLAGS_SAE_EXT_HANDLING);

	cmd.max_retries = fmac->connect_params.max_retries;
	if (fmac->connect_params.n_bssids) {
		cmd.n_bssids = fmac->connect_params.n_bssids;
		memcpy(cmd.bssids, fmac->connect_params.bssids,
		       cmd.n_bssids * ETH_ALEN);
		if (fmac->connect_params.is_whitelist)
			cmd.flags |= cpu_to_le32(IWL_FMAC_CONNECT_FLAGS_BSSID_WHITELIST);
	}

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd_pdu(fmac,
				    iwl_cmd_id(FMAC_CONNECT, FMAC_GROUP, 0),
				    0, sizeof(cmd), &cmd);
	mutex_unlock(&fmac->mutex);

	return ret;
}

static int iwl_fmac_cfg_disconnect(struct wiphy *wiphy,
				   struct net_device *dev,
				   u16 reason_code)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac_disconnect_cmd cmd = {
		.vif_id = vif->id,
		.reason = cpu_to_le16(reason_code),
	};
	u32 status = 0;
	int ret = 0;

	mutex_lock(&fmac->mutex);

	if (iwl_fmac_is_radio_killed(fmac)) {
		struct iwl_fmac_sta *sta;

		sta = rcu_dereference_protected(vif->u.mgd.ap_sta,
						lockdep_is_held(&fmac->mutex));
		iwl_fmac_disconnected(fmac, sta, cmd.reason, 0);
	} else {
		netif_tx_stop_all_queues(dev);

		/* FMAC_DISCONNECTED notification will do the rest:
		 * - synchronize_net()
		 * - flush queues
		 * - netif_carrier_off
		 * - remote the station
		 * - etc...
		 * Note that we will handle FMAC_DISCONNECTED before we
		 * exit this function.
		 */

		ret = iwl_fmac_send_cmd_pdu_status(fmac,
						   iwl_cmd_id(FMAC_DISCONNECT,
							      FMAC_GROUP, 0),
						   sizeof(cmd), &cmd, &status);
	}

	/*
	 * if we got a disconnect notification (we will if the status is
	 * successful), we'll have gotten it before the command response,
	 * so it's already queued. Force processing it so we can turn
	 * around and connect again without having to rely on scheduling
	 * decisions letting the worker run first.
	 */
	iwl_fmac_process_async_handlers(fmac);

	mutex_unlock(&fmac->mutex);

	/* The firmware will reply with a disconnection notification when
	 * the disconnection will be complete. That one will call
	 * cfg80211_disconnected().
	 */

	if (ret)
		return ret;
	if (status)
		return -ENOTCONN;

	return 0;
}

static int iwl_fmac_fill_rate_info(int rate, struct rate_info *rinfo)
{
	if (rate == 0)
		return -EINVAL;

	memset(rinfo, 0, sizeof(*rinfo));

	if (rate & RATE_MCS_HT_MSK) {
		WARN_ON(rate & RATE_MCS_VHT_MSK);
		rinfo->flags |= RATE_INFO_FLAGS_MCS;
		rinfo->mcs = rate & RATE_HT_MCS_INDEX_MSK;
	} else if (rate & RATE_MCS_VHT_MSK) {
		WARN_ON(rate & RATE_MCS_CCK_MSK);
		rinfo->flags |= RATE_INFO_FLAGS_VHT_MCS;
		rinfo->mcs = rate & RATE_VHT_MCS_RATE_CODE_MSK;
		rinfo->nss = ((rate & RATE_VHT_MCS_NSS_MSK) >>
			      RATE_VHT_MCS_NSS_POS) + 1;
	} else if (rate & RATE_MCS_HE_MSK) {
		rinfo->flags |= RATE_INFO_FLAGS_HE_MCS;
		rinfo->mcs = rate & RATE_VHT_MCS_RATE_CODE_MSK;
		rinfo->nss = ((rate & RATE_VHT_MCS_NSS_MSK) >>
			      RATE_VHT_MCS_NSS_POS) + 1;
		rinfo->he_dcm = !!(rate & RATE_HE_DUAL_CARRIER_MODE_MSK);

		switch ((rate & RATE_MCS_HE_GI_LTF_MSK) >>
			RATE_MCS_HE_GI_LTF_POS) {
		case 0:
		case 1:
			rinfo->he_gi = NL80211_RATE_INFO_HE_GI_0_8;
			break;
		case 2:
			rinfo->he_gi = NL80211_RATE_INFO_HE_GI_1_6;
			break;
		case 3:
			rinfo->he_gi = NL80211_RATE_INFO_HE_GI_3_2;
			break;
		}
	} else if (rate & RATE_MCS_CCK_MSK) {
		rinfo->legacy = (rate & RATE_LEGACY_RATE_MSK);
	} else {
		switch (rate & RATE_LEGACY_RATE_MSK) {
		case 0xD:
			rinfo->legacy = 60;
			break;
		case 0xF:
			rinfo->legacy = 90;
			break;
		case 0x5:
			rinfo->legacy = 120;
			break;
		case 0x7:
			rinfo->legacy = 180;
			break;
		case 0x9:
			rinfo->legacy = 240;
			break;
		case 0xB:
			rinfo->legacy = 360;
			break;
		case 0x1:
			rinfo->legacy = 480;
			break;
		case 0x3:
			rinfo->legacy = 540;
			break;
		default:
			WARN_ON(1);
			return -EINVAL;
		}
	}

	switch (rate & RATE_MCS_CHAN_WIDTH_MSK) {
	case RATE_MCS_CHAN_WIDTH_20:
		rinfo->bw = RATE_INFO_BW_20;
		if (rate & RATE_MCS_HE_MSK)
			rinfo->he_ru_alloc = NL80211_RATE_INFO_HE_RU_ALLOC_242;
		break;
	case RATE_MCS_CHAN_WIDTH_40:
		rinfo->bw = RATE_INFO_BW_40;
		if (rate & RATE_MCS_HE_MSK)
			rinfo->he_ru_alloc = NL80211_RATE_INFO_HE_RU_ALLOC_484;
		break;
	case RATE_MCS_CHAN_WIDTH_80:
		rinfo->bw = RATE_INFO_BW_80;
		if (rate & RATE_MCS_HE_MSK)
			rinfo->he_ru_alloc = NL80211_RATE_INFO_HE_RU_ALLOC_996;
		break;
	case RATE_MCS_CHAN_WIDTH_160:
		rinfo->bw = RATE_INFO_BW_160;
		if (rate & RATE_MCS_HE_MSK)
			rinfo->he_ru_alloc =
				NL80211_RATE_INFO_HE_RU_ALLOC_2x996;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	if ((rate & RATE_MCS_HE_TYPE_MSK) == RATE_MCS_HE_TYPE_MU)
		rinfo->bw = RATE_INFO_BW_HE_RU;

	if (rate & RATE_MCS_SGI_MSK)
		rinfo->flags |= RATE_INFO_FLAGS_SHORT_GI;

	return 0;
}

static void iwl_fmac_set_sta_rx_sinfo(const struct iwl_fmac_sta *sta,
				      struct station_info *sinfo)
{
	struct iwl_fmac_rx_stats *last_rx_stats = NULL;
	int cpu;

	sinfo->filled |= BIT(NL80211_STA_INFO_RX_PACKETS);
	sinfo->rx_packets = 0;

	for_each_possible_cpu(cpu) {
		struct iwl_fmac_rx_stats *cpu_stats =
			per_cpu_ptr(sta->info.pcpu_rx_stats, cpu);

		if (!last_rx_stats ||
		    time_after(cpu_stats->last_rx, last_rx_stats->last_rx))
			last_rx_stats = cpu_stats;

		sinfo->rx_packets += cpu_stats->packets;
	}

	if (iwl_fmac_fill_rate_info(last_rx_stats->last_rate,
				    &sinfo->rxrate) == 0)
		sinfo->filled |= BIT(NL80211_STA_INFO_RX_BITRATE);

	sinfo->filled |= BIT(NL80211_STA_INFO_SIGNAL);
	sinfo->signal = MBM_TO_DBM(last_rx_stats->signal);
}

static void iwl_fmac_set_sta_tx_sinfo(const struct iwl_fmac_sta *sta,
				      struct station_info *sinfo)
{
	if (iwl_fmac_fill_rate_info(sta->info.tx_stats.last_rate,
				    &sinfo->txrate) == 0)
		sinfo->filled |= BIT(NL80211_STA_INFO_TX_BITRATE);

	sinfo->filled |= BIT(NL80211_STA_INFO_TX_BYTES64);
	sinfo->tx_bytes = sta->info.tx_stats.bytes;

	sinfo->filled |= BIT(NL80211_STA_INFO_TX_PACKETS);
	sinfo->tx_packets = sta->info.tx_stats.packets;

	sinfo->filled |= BIT(NL80211_STA_INFO_TX_RETRIES);
	sinfo->tx_retries = sta->info.tx_stats.retries;

	sinfo->filled |= BIT(NL80211_STA_INFO_TX_FAILED);
	sinfo->tx_failed = sta->info.tx_stats.failed;
}

static void iwl_fmac_set_sta_info(const struct iwl_fmac_sta *sta,
				  struct station_info *sinfo)
{
	struct iwl_fmac *fmac = sta->vif->fmac;

	lockdep_assert_held(&fmac->mutex);

	sinfo->filled = 0;

	sinfo->generation = fmac->sta_generation;

	sinfo->filled |= BIT(NL80211_STA_INFO_CONNECTED_TIME);
	sinfo->connected_time = ktime_get_seconds() - sta->info.connect_time;

	sinfo->sta_flags.mask = 0;
	sinfo->filled |= BIT(NL80211_STA_INFO_STA_FLAGS);

	if (sta->authorized)
		sinfo->sta_flags.set |= BIT(NL80211_STA_FLAG_AUTHORIZED);
	sinfo->sta_flags.mask |= BIT(NL80211_STA_FLAG_AUTHORIZED);

	iwl_fmac_set_sta_tx_sinfo(sta, sinfo);

	iwl_fmac_set_sta_rx_sinfo(sta, sinfo);
}

static int iwl_fmac_get_station(struct wiphy *wiphy, struct net_device *dev,
				const u8 *mac, struct station_info *sinfo)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_sta *sta;
	int ret = -ENOENT;

	mutex_lock(&fmac->mutex);
	sta = iwl_get_sta(fmac, mac);
	if (sta) {
		ret = 0;
		iwl_fmac_set_sta_info(sta, sinfo);
	}
	mutex_unlock(&fmac->mutex);

	return ret;
}

static int iwl_fmac_dump_station(struct wiphy *wiphy, struct net_device *dev,
				 int idx, u8 *mac, struct station_info *sinfo)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_sta *sta;
	int tmp;

	mutex_lock(&fmac->mutex);
	for_each_valid_sta(fmac, sta, tmp) {
		if (idx > 0) {
			idx--;
			continue;
		}

		ether_addr_copy(mac, sta->addr);
		iwl_fmac_set_sta_info(sta, sinfo);
		mutex_unlock(&fmac->mutex);
		return 0;
	}
	mutex_unlock(&fmac->mutex);

	return -ENOENT;
}

static int iwl_fmac_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);

	if (changed & WIPHY_PARAM_FRAG_THRESHOLD)
		fmac->rts_threshold = wiphy->rts_threshold;

	return 0;
}

u8 cfg_width_to_iwl_width(enum nl80211_chan_width cfg_width)
{
	switch (cfg_width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		return IWL_CHAN_WIDTH_20_NOHT;
	case NL80211_CHAN_WIDTH_20:
		return IWL_CHAN_WIDTH_20;
	case NL80211_CHAN_WIDTH_40:
		return IWL_CHAN_WIDTH_40;
	case NL80211_CHAN_WIDTH_80:
		return IWL_CHAN_WIDTH_80;
	case NL80211_CHAN_WIDTH_160:
		return IWL_CHAN_WIDTH_160;
	default:
		break;
	}

	WARN_ON(1); /* shouldn't get here */
	return IWL_NUM_CHAN_WIDTH;
}

u16 iwl_fmac_parse_rates(struct wiphy *wiphy, struct iwl_fmac_vif *vif,
			 const u8 *rates, u8 rates_len)
{
	const struct ieee80211_supported_band *sband =
		wiphy->bands[vif->chan->band];
	const u8 *end = rates + rates_len;
	u16 rates_bm = 0;

	while (rates != end) {
		u8 rate = *rates++;
		int i;

		for (i = 0; i < sband->n_bitrates; i++) {
			if (sband->bitrates[i].bitrate / 5 != rate)
				continue;

			rates_bm |= BIT(sband->bitrates[i].hw_value);
			break;
		}
	}

	return rates_bm;
}

static int iwl_fmac_set_power_mgmt(struct wiphy *wiphy, struct net_device *dev,
				   bool enabled, int timeout)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	int ret;

	IWL_DEBUG_POWER(fmac, "set_power_mgmt enabled=%d\n", enabled);

	if (vif->wdev.iftype != NL80211_IFTYPE_STATION)
		return -EOPNOTSUPP;

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_config_u32(fmac, vif->id,
				       IWL_FMAC_CONFIG_VIF_POWER_DISABLED,
				       enabled ? 0 : 1);
	mutex_unlock(&fmac->mutex);

	return ret;
}

static int iwl_fmac_set_wdev_tx_power(struct iwl_fmac *fmac,
				      struct wireless_dev *wdev,
				      int user_power_level)
{
	struct iwl_fmac_vif *vif = vif_from_wdev(wdev);

	return iwl_fmac_send_config_u32(fmac, vif->id,
					IWL_FMAC_CONFIG_VIF_TXPOWER_USER,
					user_power_level);
}

static int iwl_fmac_set_tx_power(struct wiphy *wiphy,
				 struct wireless_dev *wdev,
				 enum nl80211_tx_power_setting txp_type,
				 int mbm)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	int user_power_level;

	switch (txp_type) {
	case NL80211_TX_POWER_AUTOMATIC:
		user_power_level = IWL_FMAC_POWER_LEVEL_UNSET;
		break;
	case NL80211_TX_POWER_LIMITED:
		if (mbm < 0 || (mbm % 100))
			return -EOPNOTSUPP;
		user_power_level = MBM_TO_DBM(mbm);
		break;
	case NL80211_TX_POWER_FIXED:
	default:
		return -EOPNOTSUPP;
	}

	mutex_lock(&fmac->mutex);

	if (wdev) {
		iwl_fmac_set_wdev_tx_power(fmac, wdev, user_power_level);
	} else {
		list_for_each_entry(wdev, &wiphy->wdev_list, list)
			iwl_fmac_set_wdev_tx_power(fmac, wdev,
						   user_power_level);
	}

	mutex_unlock(&fmac->mutex);

	return 0;
}

static int iwl_fmac_mgmt_tx(struct wiphy *wiphy,
			    struct wireless_dev *wdev,
			    struct cfg80211_mgmt_tx_params *params,
			    u64 *cookie)

{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_wdev(wdev);
	const struct ieee80211_mgmt *mgmt = (void *)params->buf;
	struct iwl_fmac_tx_data tx = {};
	struct iwl_fmac_skb_info *info;
	struct sk_buff *skb;

	if (vif->wdev.iftype != NL80211_IFTYPE_STATION)
		return -EOPNOTSUPP;

	mutex_lock(&fmac->mutex);

	skb = dev_alloc_skb(params->len);
	if (!skb) {
		mutex_unlock(&fmac->mutex);
		return -ENOMEM;
	}
	info = (void *)skb->cb;
	memset(info, 0, sizeof(*info));

	tx.sta = iwl_get_sta(fmac, mgmt->da);

	*cookie = ++vif->cookie;
	info->cookie = *cookie;

	if (WARN_ON(!tx.sta)) {
		mutex_unlock(&fmac->mutex);
		return -EINVAL;
	}

	if ((vif->chan && vif->chan->band == NL80211_BAND_5GHZ) ||
	    tx.sta->band == NL80211_BAND_5GHZ)
		tx.flags |= IWL_FMAC_SKB_INFO_FLAG_BAND_5;

	if (params->no_cck)
		tx.flags |= IWL_FMAC_SKB_INFO_FLAG_NO_CCK;

	skb_reset_transport_header(skb);
	skb_put_data(skb, params->buf, params->len);

	iwl_fmac_tx_skb(fmac, skb, &tx);

	mutex_unlock(&fmac->mutex);

	return 0;
}

static int iwl_fmac_suspend(struct wiphy *wiphy,
			    struct cfg80211_wowlan *wowlan)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);

	/* TODO: Wowlan */

	mutex_lock(&fmac->mutex);
	iwl_fmac_stop_device(fmac);
	mutex_unlock(&fmac->mutex);

	return 0;
}

static int iwl_fmac_resume(struct wiphy *wiphy)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);

	/*
	 * TODO: Wowlan.
	 * For now we run a full NIC restart here instead of tearing down the
	 * connections in suspend flow and restoring them here.
	 */
	iwl_fmac_nic_restart(fmac, false);

	return 0;
}

static int iwl_fmac_set_qos_map(struct wiphy *wiphy,
				struct net_device *dev,
				struct cfg80211_qos_map *qos_map)
{
	struct iwl_fmac_qos_map *fmac_prev_qos_map, *fmac_next_qos_map;
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);

	if (!qos_map) {
		fmac_next_qos_map = NULL;
		goto out;
	}

	fmac_next_qos_map = kzalloc(sizeof(*fmac_next_qos_map), GFP_KERNEL);
	if (!fmac_next_qos_map)
		return -ENOMEM;
	memcpy(&fmac_next_qos_map->qos_map, qos_map,
	       sizeof(fmac_next_qos_map->qos_map));

out:
	fmac_prev_qos_map =
		rcu_dereference_protected(vif->qos_map,
					  lockdep_is_held(&vif->wdev.mtx));

	rcu_assign_pointer(vif->qos_map, fmac_next_qos_map);

	if (fmac_prev_qos_map)
		kfree_rcu(fmac_prev_qos_map, rcu_head);

	return 0;
}

static int iwl_fmac_set_pmk(struct wiphy *wiphy, struct net_device *dev,
			    const struct cfg80211_pmk_conf *conf)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac_mlme_set_pmk_cmd cmd = {
		.vif_id = vif->id,
	};
	int ret;

	if (!conf->pmk)
		return -EINVAL;

	/* FT authentication is currently not supported */
	if (conf->pmk_r0_name)
		return -ENOTSUPP;

	switch (conf->pmk_len) {
	case WLAN_PMK_LEN:
		cmd.key_type = IWL_FMAC_KEY_TYPE_PMK;
		break;
	case WLAN_PMK_LEN_EAP_LEAP:
		cmd.key_type = IWL_FMAC_KEY_TYPE_PMK_EAP_LEAP;
		break;
	case WLAN_PMK_LEN_SUITE_B_192:
		cmd.key_type = IWL_FMAC_KEY_TYPE_PMK_SUITE_B_192;
		break;
	default:
		return -EINVAL;
	}

	memcpy(cmd.aa, conf->aa, ETH_ALEN);
	memcpy(cmd.key, conf->pmk, conf->pmk_len);

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd_pdu(fmac,
				    iwl_cmd_id(FMAC_SET_PMK, FMAC_GROUP, 0),
				    0, sizeof(cmd), &cmd);
	mutex_unlock(&fmac->mutex);

	return ret;
}

static int iwl_fmac_del_pmk(struct wiphy *wiphy, struct net_device *dev,
			    const u8 *aa)
{
	return -ENOTSUPP;
}

static int iwl_fmac_external_auth(struct wiphy *wiphy, struct net_device *dev,
				  struct cfg80211_external_auth_params *params)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	int ret;
	struct iwl_fmac_external_auth cmd = {
		.vif_id = vif->id,
	};

	cmd.action = params->action;
	memcpy(cmd.bssid, params->bssid, ETH_ALEN);
	cmd.key_mgmt_suite = cpu_to_le32(params->key_mgmt_suite);
	cmd.status = cpu_to_le16(params->status);
	cmd.ssid_len = params->ssid.ssid_len;
	if (params->ssid.ssid_len)
		memcpy(cmd.ssid, params->ssid.ssid, sizeof(cmd.ssid));

	if (params->pmk_len) {
		if (params->pmk_len != sizeof(cmd.pmk))
			return -ENOTSUPP;
		memcpy(cmd.pmkid, params->pmkid, sizeof(cmd.pmkid));
		memcpy(cmd.pmk, params->pmk, sizeof(cmd.pmk));
	}

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd_pdu(fmac,
				    iwl_cmd_id(FMAC_EXTERNAL_AUTH_STATUS,
					       FMAC_GROUP, 0),
				    0, sizeof(cmd), &cmd);
	mutex_unlock(&fmac->mutex);

	return ret;
}

const struct cfg80211_ops iwl_fmac_cfg_ops = {
	.add_virtual_intf = iwl_fmac_cfg_add_virtual_intf,
	.del_virtual_intf = iwl_fmac_cfg_del_virtual_intf,
	.change_virtual_intf = iwl_fmac_cfg_change_virtual_intf,
	.scan = iwl_fmac_cfg_scan,
	.abort_scan = iwl_fmac_cfg_abort_scan,
	.connect = iwl_fmac_cfg_connect,
	.disconnect = iwl_fmac_cfg_disconnect,
	.get_station = iwl_fmac_get_station,
	.dump_station = iwl_fmac_dump_station,
	.set_wiphy_params = iwl_fmac_set_wiphy_params,
	.set_power_mgmt = iwl_fmac_set_power_mgmt,
	.suspend = iwl_fmac_suspend,
	.resume = iwl_fmac_resume,
	.set_tx_power = iwl_fmac_set_tx_power,
	.set_qos_map = iwl_fmac_set_qos_map,
	.set_pmk = iwl_fmac_set_pmk,
	.del_pmk = iwl_fmac_del_pmk,
	.mgmt_tx = iwl_fmac_mgmt_tx,
	.external_auth = iwl_fmac_external_auth,
};

static u32 iwl_fmac_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_GCMP,
	WLAN_CIPHER_SUITE_GCMP_256,

	/*
	 * Note: These ciphers are chopped in case iwl_fmac_has_new_tx_api()
	 * is false, i.e., for 9000 devices.
	 */
	WLAN_CIPHER_SUITE_AES_CMAC,
	WLAN_CIPHER_SUITE_BIP_CMAC_256,
	WLAN_CIPHER_SUITE_BIP_GMAC_128,
	WLAN_CIPHER_SUITE_BIP_GMAC_256,
};

#define SCAN_OFFLOAD_PROBE_REQ_SIZE 512

static u16 iwl_fmac_max_scan_ie_len(void)
{
	const int internal_preq_size =
		24 + /* header */
		2 + /* ssid ie (without the actual ssid) */
		3 + /* ds ie */
		2 + 2 + 12 + /* (ext) supported rates 2.4 (12 rates) */
		2 + 8 + /* supported rates 5 (8 rates ) */
		sizeof(struct ieee80211_ht_cap) + 2 + /* ht 2.4 */
		sizeof(struct ieee80211_ht_cap) + 2 + /* ht 5 */
		sizeof(struct ieee80211_vht_cap) + 2; /* vht 5 */

	return SCAN_OFFLOAD_PROBE_REQ_SIZE - internal_preq_size;
}

void iwl_fmac_setup_wiphy(struct iwl_fmac *fmac)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	u8 num_mac;
	int i;

	set_wiphy_dev(wiphy, fmac->dev);
	snprintf(wiphy->fw_version, sizeof(wiphy->fw_version),
		 "%s", fmac->fw->fw_version);

	/* iface_combinations, software_iftypes */

	wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION);

	wiphy->flags = WIPHY_FLAG_NETNS_OK |
		       /* WIPHY_FLAG_SUPPORTS_SCHED_SCAN | */
		       /* WIPHY_FLAG_SUPPORTS_FW_ROAM | ?? */
		       WIPHY_FLAG_HAS_STATIC_WEP;

	wiphy->features = NL80211_FEATURE_SCAN_RANDOM_MAC_ADDR |
			  NL80211_FEATURE_MAC_ON_CREATE |
			  NL80211_FEATURE_SK_TX_STATUS |
			  NL80211_FEATURE_SAE;

	if (iwlfmac_mod_params.power_scheme == FMAC_PS_MODE_CAM)
		wiphy->flags &= ~WIPHY_FLAG_PS_ON_BY_DEFAULT;
	else
		wiphy->flags |= WIPHY_FLAG_PS_ON_BY_DEFAULT;

	wiphy->flags |= WIPHY_FLAG_REPORTS_OBSS;

	/* LAR (DRS) is always supported in FMAC FWs */
	wiphy->regulatory_flags |= REGULATORY_WIPHY_SELF_MANAGED |
				   REGULATORY_ENABLE_RELAX_NO_IR;

	wiphy_ext_feature_set(wiphy,
			      NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);
	wiphy_ext_feature_set(wiphy,
			      NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X);

	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;
	wiphy->hw_version = fmac->trans->hw_id;

	wiphy->cipher_suites = iwl_fmac_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(iwl_fmac_cipher_suites);

	/* we don't support MFP on 9000 devices */
	if (iwl_fmac_has_new_tx_api(fmac))
		wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_MFP_OPTIONAL);
	else
		wiphy->n_cipher_suites -= 4;

	/* Extract MAC address */
	ether_addr_copy(fmac->addresses[0].addr, fmac->nvm_data->hw_addr);
	wiphy->addresses = fmac->addresses;
	wiphy->n_addresses = 1;

	/* Extract additional MAC addresses if available */
	num_mac = (fmac->nvm_data->n_hw_addrs > 1) ?
		min(IWL_MAX_ADDRESSES, fmac->nvm_data->n_hw_addrs) : 1;
#ifdef CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES
	if (fmac->trans->dbg_cfg.hw_address.len) {
		num_mac = IWL_MAX_ADDRESSES;
	}
#endif

	for (i = 1; i < num_mac; i++) {
		ether_addr_copy(fmac->addresses[i].addr,
				fmac->addresses[i - 1].addr);
		fmac->addresses[i].addr[5]++;
		wiphy->n_addresses++;
	}

	wiphy->max_scan_ssids = IWL_FMAC_MAX_SSIDS;
	wiphy->max_scan_ie_len = iwl_fmac_max_scan_ie_len();

	if (fmac->nvm_data->bands[NL80211_BAND_2GHZ].n_channels)
		wiphy->bands[NL80211_BAND_2GHZ] =
			&fmac->nvm_data->bands[NL80211_BAND_2GHZ];
	if (fmac->nvm_data->bands[NL80211_BAND_5GHZ].n_channels) {
		wiphy->bands[NL80211_BAND_5GHZ] =
			&fmac->nvm_data->bands[NL80211_BAND_5GHZ];

		/* TODO: IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE
		 *	 we can probably set it always...
		 */
	}

	fmac->rts_threshold = IEEE80211_MAX_RTS_THRESHOLD;
	wiphy->rts_threshold = fmac->rts_threshold;

	iwl_fmac_set_wiphy_vendor_commands(wiphy);
}

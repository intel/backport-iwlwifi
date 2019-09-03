/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright (C) 2018 Intel Corporation
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
 * Copyright (C) 2018 Intel Corporation
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
#include "iwl-debug.h"

#include "fmac.h"

const u8 tid_to_ac[] = {
	AC_BE,
	AC_BK,
	AC_BK,
	AC_BE,
	AC_VI,
	AC_VI,
	AC_VO,
	AC_VO,
};

int iwl_fmac_alloc_sta(struct iwl_fmac *fmac, struct iwl_fmac_vif *vif,
		       u8 sta_id, const u8 *addr)
{
	struct iwl_fmac_sta *sta;
	int i;

	lockdep_assert_held(&fmac->mutex);

	if (WARN_ON(sta_id >= IWL_FMAC_MAX_STA))
		return -EINVAL;

	if (WARN_ON(fmac->stas[sta_id]))
		return -EBUSY;

	sta = kzalloc(sizeof(*sta), GFP_KERNEL);
	if (!sta)
		return -ENOMEM;

	sta->vif = vif;
	sta->sta_id = sta_id;
	/* Kcalloc zeroes the data */
	sta->dup_data = kcalloc(fmac->trans->num_rx_queues,
				sizeof(*sta->dup_data),
				GFP_KERNEL);
	if (!sta->dup_data) {
		kfree(sta);
		return -ENOMEM;
	}

	/*
	 * Initialize all the last_seq values to 0xffff which can only
	 * compare equal to the frame's seq_ctrl in the check when
	 * somehow the very first frame received is the last fragment
	 * with the right sequence number - but that would be dropped
	 * anyway since we don't have the other fragments.
	 *
	 * This thus allows receiving a packet with seqno 0 and the
	 * retry bit set as the very first packet on a new TID.
	 */
	for (i = 0; i < fmac->trans->num_rx_queues; i++)
		memset(sta->dup_data[i].last_seq, 0xff,
		       sizeof(sta->dup_data[i].last_seq));

	memcpy(sta->addr, addr, ETH_ALEN);

	spin_lock_init(&sta->lock);

	/* Data path initializations */

	spin_lock_init(&sta->amsdu_lock);

	for (i = 0; i < ARRAY_SIZE(sta->tids); i++) {
		sta->tids[i].txq_id = IWL_FMAC_INVALID_TXQ_ID;
		skb_queue_head_init(&sta->tids[i].deferred_tx_frames);
	}

	sta->info.connect_time = ktime_get_seconds();
	sta->info.pcpu_rx_stats = alloc_percpu(struct iwl_fmac_rx_stats);
	if (!sta->info.pcpu_rx_stats) {
		kfree(sta->dup_data);
		kfree(sta);
		return -ENOMEM;
	}

	rcu_assign_pointer(fmac->stas[sta_id], sta);

	iwl_fmac_dbgfs_add_sta(fmac, sta);
	return 0;
}

static int iwl_fmac_flush_sta_queues_tvqm(struct iwl_fmac *fmac,
					  struct iwl_fmac_sta *sta)
{
	struct iwl_tx_path_flush_cmd cmd = {
		.sta_id = cpu_to_le32(sta->sta_id),
		.tid_mask = cpu_to_le16(0xff | BIT(IWL_MGMT_TID)),
	};

	return iwl_fmac_send_cmd_pdu(fmac, TXPATH_FLUSH, 0, sizeof(cmd), &cmd);
}

static int iwl_fmac_flush_sta_queues_9000(struct iwl_fmac *fmac,
					  struct iwl_fmac_sta *sta)
{
	struct iwl_tx_path_flush_cmd_v1 cmd = {};
	u32 tfd_q_mask = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(sta->tids); i++) {
		u16 txq_id = sta->tids[i].txq_id;

		if (txq_id != IWL_FMAC_INVALID_TXQ_ID) {
			if (WARN_ON(txq_id >= IWL_MAX_HW_QUEUES))
				continue;
			tfd_q_mask |= BIT(txq_id);
		}
	}

	IWL_DEBUG_TX_QUEUES(fmac, "Flushing queues 0x%x for sta %pM\n",
			    tfd_q_mask, sta->addr);

	cmd.queues_ctl = cpu_to_le32(tfd_q_mask);
	cmd.flush_ctl = cpu_to_le16(DUMP_TX_FIFO_FLUSH);

	return iwl_fmac_send_cmd_pdu(fmac, TXPATH_FLUSH, 0, sizeof(cmd), &cmd);
}

void iwl_fmac_flush_sta_queues(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta)
{
	if (!iwl_fmac_has_new_tx_api(fmac))
		iwl_fmac_flush_sta_queues_9000(fmac, sta);
	else
		iwl_fmac_flush_sta_queues_tvqm(fmac, sta);
}

static void iwl_fmac_remove_sta(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta)
{
	RCU_INIT_POINTER(fmac->stas[sta->sta_id], NULL);

	/* sanity check that it was removed elsewhere */
	switch (sta->vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_P2P_CLIENT:
		WARN_ON(rcu_access_pointer(sta->vif->u.mgd.ap_sta) == sta);
		break;
	default:
		/* nothing */
		break;
	}
}

void iwl_fmac_destroy_sta_keys(struct iwl_fmac *fmac,
			       struct iwl_fmac_sta *sta)
{
	int i;

	BUILD_BUG_ON(ARRAY_SIZE(sta->ptk) > ARRAY_SIZE(sta->gtk));
	for (i = 0; i < ARRAY_SIZE(sta->ptk); i++) {
		struct iwl_fmac_sta_key *gtk;
		struct iwl_fmac_sta_key *tmp =
			rcu_dereference_protected(sta->ptk[i],
				lockdep_is_held(&fmac->mutex));

		/* In WEP the same key is stored in both PTK and GTK arrays,
		 * prevent double free.
		 */
		gtk = rcu_dereference_protected(sta->gtk[i],
						lockdep_is_held(&fmac->mutex));
		if (gtk == tmp)
			RCU_INIT_POINTER(sta->gtk[i], NULL);

		kfree(tmp);
		RCU_INIT_POINTER(sta->ptk[i], NULL);
	}

	for (i = 0; i < ARRAY_SIZE(sta->gtk); i++) {
		struct iwl_fmac_sta_key *tmp =
			rcu_dereference_protected(sta->gtk[i],
				lockdep_is_held(&fmac->mutex));

		kfree(tmp);
		RCU_INIT_POINTER(sta->gtk[i], NULL);
	}
}

void iwl_fmac_destroy_sta_tids(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			       bool hw_error)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sta->tids); i++) {
		struct iwl_fmac_tid *tid_data = &sta->tids[i];
		u16 txq_id = tid_data->txq_id;
		struct sk_buff *skb;

		if (txq_id != IWL_FMAC_INVALID_TXQ_ID) {
			if (hw_error) {
				tid_data->txq_id = IWL_FMAC_INVALID_TXQ_ID;
				fmac->queue_sta_map[txq_id] =
					IWL_FMAC_INVALID_STA_ID;
			} else {
				iwl_fmac_release_txq(fmac, sta, txq_id, i);
			}
		}

		clear_bit(sta->sta_id, fmac->sta_deferred_frames);
		spin_lock_bh(&sta->lock);
		if (sta->deferred_traffic_tid_map & BIT(i)) {
			sta->deferred_traffic_tid_map &= ~BIT(i);
			while ((skb =
				__skb_dequeue(&tid_data->deferred_tx_frames)))
				dev_kfree_skb_any(skb);
			iwl_fmac_wake_ac_queue(fmac, &sta->vif->wdev,
					       tid_to_ac[i]);
		}
		spin_unlock_bh(&sta->lock);
	}
}

static void iwl_fmac_destroy_sta(struct iwl_fmac *fmac,
				 struct iwl_fmac_sta *sta,
				 bool hw_error)
{
	int i;

	if (likely(!hw_error))
		iwl_fmac_flush_sta_queues(fmac, sta);

	iwl_fmac_destroy_sta_tids(fmac, sta, hw_error);

	iwl_fmac_destroy_sta_keys(fmac, sta);

	for (i = 0; i < IWL_MAX_BAID; i++) {
		int q;

		for (q = 0; q < fmac->trans->num_rx_queues; q++) {
			struct iwl_fmac_reorder_buffer *buffer;

			buffer = &fmac->reorder_bufs[i][q];

			if (buffer->sta_id == sta->sta_id)
				iwl_fmac_destroy_reorder_buffer(fmac, sta,
								buffer);
		}
	}

	for (i = 0; i < ARRAY_SIZE(sta->amsdu); i++) {
		if (sta->amsdu[i].skb)
			dev_kfree_skb(sta->amsdu[i].skb);
	}

	iwl_fmac_dbgfs_del_sta(fmac, sta);

	if (likely(!hw_error)) {
		if (sta->vif->wdev.iftype != NL80211_IFTYPE_AP) {
			struct iwl_fmac_sta_removed cmd = {
				.vif_id = sta->vif->id,
				.sta_id = sta->sta_id,
			};

			/* acknowledge the removal to the firmware */
			WARN(iwl_fmac_send_cmd_pdu(fmac,
					iwl_cmd_id(FMAC_ACK_STA_REMOVED,
						   FMAC_GROUP, 0), 0,
						   sizeof(cmd), &cmd),
			     "Failed to acknowledge station removal\n");
		} else {
			struct iwl_fmac_host_ap_sta_cmd cmd = {
				.action = IWL_FMAC_REM_HOST_BASED_STA,
				.sta_id = sta->sta_id,
				.vif_id = sta->vif->id,
			};
			WARN(iwl_fmac_send_cmd_pdu(fmac,
					iwl_cmd_id(FMAC_HOST_BASED_AP_STA,
						   FMAC_GROUP, 0), 0,
						   sizeof(cmd), &cmd),
			     "Failed to remove the station\n");
		}
	}

	kfree(sta->dup_data);
	kfree(sta);
}

void iwl_fmac_free_sta(struct iwl_fmac *fmac, u8 sta_id, bool hw_error)
{
	struct iwl_fmac_sta *sta;

	sta = rcu_dereference_protected(fmac->stas[sta_id],
					lockdep_is_held(&fmac->mutex));

	if (WARN(!sta, "freeing sta_id %d but it doesn't exist", sta_id))
		return;

	iwl_fmac_remove_sta(fmac, sta);

	synchronize_net();

	iwl_fmac_destroy_sta(fmac, sta, hw_error);
}

void iwl_fmac_free_stas(struct iwl_fmac *fmac,
			struct iwl_fmac_vif *vif,
			bool hw_error)
{
	struct iwl_fmac_sta *stas[ARRAY_SIZE(fmac->stas)] = {};
	struct iwl_fmac_sta *sta;
	int tmp, idx = 0;

	for_each_valid_sta(fmac, sta, tmp) {
		if (sta->vif != vif)
			continue;
		stas[idx] = sta;
		idx++;
		iwl_fmac_remove_sta(fmac, sta);
	}

	synchronize_net();

	for (idx = 0; idx < ARRAY_SIZE(fmac->stas); idx++) {
		if (!stas[idx])
			break;
		iwl_fmac_destroy_sta(fmac, stas[idx], hw_error);
	}
}

static void iwl_fmac_tx_deferred_stream(struct iwl_fmac *fmac,
					struct iwl_fmac_sta *sta, int tid)
{
	struct iwl_fmac_tid *tid_data = &sta->tids[tid];
	struct sk_buff *skb;
	struct ieee80211_hdr *hdr;
	struct sk_buff_head deferred_tx;
	bool no_queue = false; /* Marks if there is a problem with the queue */
	struct iwl_fmac_tx_data tx = {
		.sta = sta,
		.vif = sta->vif,
	};

	lockdep_assert_held(&fmac->mutex);

	skb = skb_peek(&tid_data->deferred_tx_frames);
	if (!skb)
		return;
	hdr = (void *)skb->data;

	if (!WARN(tid_data->txq_id != IWL_FMAC_INVALID_TXQ_ID,
		  "STA %d already has TXQ %d for TID %d\n", sta->sta_id,
		  tid_data->txq_id, tid) &&
	    iwl_fmac_alloc_queue(fmac, sta, tid, hdr)) {
		IWL_ERR(fmac,
			"Can't alloc TXQ for sta %d tid %d - dropping frame\n",
			sta->sta_id, tid);

		/*
		 * Mark queue as problematic so later the deferred traffic is
		 * freed, as we can do nothing with it
		 */
		no_queue = true;
	}

	__skb_queue_head_init(&deferred_tx);

	/* Disable bottom-halves when entering TX path */
	local_bh_disable();
	spin_lock(&sta->lock);
	skb_queue_splice_init(&tid_data->deferred_tx_frames, &deferred_tx);
	sta->deferred_traffic_tid_map &= ~BIT(tid);
	spin_unlock(&sta->lock);

	rcu_read_lock();

	while ((skb = __skb_dequeue(&deferred_tx))) {
		iwl_fmac_tx_set_key(skb, &tx);
		if (no_queue || iwl_fmac_tx_skb(fmac, skb, &tx))
			dev_kfree_skb_any(skb);
	}
	rcu_read_unlock();
	local_bh_enable();

	/* Wake queue */
	iwl_fmac_wake_ac_queue(fmac, &sta->vif->wdev, tid_to_ac[tid]);
}

void iwl_fmac_add_new_stream_wk(struct work_struct *wk)
{
	struct iwl_fmac *fmac = container_of(wk, struct iwl_fmac,
					   add_stream_wk);
	struct iwl_fmac_sta *sta;
	unsigned long deferred_tid_traffic;
	int sta_id, tid;

	mutex_lock(&fmac->mutex);

	/* Go over all stations with deferred traffic */
	for_each_set_bit(sta_id, fmac->sta_deferred_frames, IWL_FMAC_MAX_STA) {
		clear_bit(sta_id, fmac->sta_deferred_frames);
		sta = rcu_dereference_protected(fmac->stas[sta_id],
						lockdep_is_held(&fmac->mutex));
		if (WARN(!sta, "sta %d doesn't exist anymore",
			 sta_id)) /* Maybe STA was removed by now */
			continue;

		deferred_tid_traffic = sta->deferred_traffic_tid_map;

		for_each_set_bit(tid, &deferred_tid_traffic, IWL_MAX_TID_COUNT)
			iwl_fmac_tx_deferred_stream(fmac, sta, tid);
	}

	mutex_unlock(&fmac->mutex);
}

int iwl_fmac_sta_rm_key(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			bool pairwise, u8 keyidx)
{
	lockdep_assert_held(&fmac->mutex);

	if (pairwise) {
		struct iwl_fmac_sta_key *key_tmp =
			rcu_dereference_protected(sta->ptk[keyidx],
						  lockdep_is_held(&fmac->mutex));
		if (!key_tmp)
			return -ENOENT;

		RCU_INIT_POINTER(sta->ptk[keyidx], NULL);
		kfree_rcu(key_tmp, rcu_head);
	} else {
		struct iwl_fmac_sta_key *key_tmp =
			rcu_dereference_protected(sta->gtk[keyidx],
						  lockdep_is_held(&fmac->mutex));
		if (!key_tmp)
			return -ENOENT;

		RCU_INIT_POINTER(sta->gtk[keyidx], NULL);
		kfree_rcu(key_tmp, rcu_head);
	}

	return 0;
}

void iwl_fmac_sta_add_key(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			  bool pairwise, const struct iwl_fmac_key *fw_key)
{
	int tid, q;
	struct iwl_fmac_sta_key *new_key;

	lockdep_assert_held(&fmac->mutex);

	/* TODO: handle iGTK */

	/* In WEP the same key is stored in both PTK and GTK arrays */
	BUILD_BUG_ON(ARRAY_SIZE(sta->ptk) > ARRAY_SIZE(sta->gtk));

	if (WARN_ON_ONCE(pairwise && fw_key->keyidx >= ARRAY_SIZE(sta->ptk)))
		return;

	if (WARN_ON_ONCE(!pairwise && fw_key->keyidx >= ARRAY_SIZE(sta->gtk)))
		return;

	if (WARN_ON_ONCE(fw_key->rx_pn_len > IEEE80211_CCMP_PN_LEN))
		return;

	new_key = kzalloc(sizeof(new_key->q[0]) * fmac->trans->num_rx_queues +
			  sizeof(*new_key), GFP_KERNEL);
	if (!new_key)
		return;

	new_key->cipher = le32_to_cpu(fw_key->cipher);
	new_key->hw_keyidx = fw_key->hw_keyidx;
	new_key->keyidx = fw_key->keyidx;
	sta->encryption = true;

	BUILD_BUG_ON(IEEE80211_GCMP_HDR_LEN != IEEE80211_CCMP_HDR_LEN);

	switch (new_key->cipher) {
	case IWL_FMAC_CIPHER_GCMP:
	case IWL_FMAC_CIPHER_GCMP_256:
	case IWL_FMAC_CIPHER_CCMP:
	case IWL_FMAC_CIPHER_CCMP_256:
		new_key->iv_len = IEEE80211_CCMP_HDR_LEN;
		break;
	case IWL_FMAC_CIPHER_TKIP:
		new_key->iv_len = IEEE80211_TKIP_IV_LEN;

		if (!fmac->trans->cfg->gen2 && !pairwise)
			memcpy(new_key->tkip_mcast_rx_mic_key,
			       fw_key->tkip_mcast_rx_mic_key,
			       IWL_TKIP_MCAST_RX_MIC_KEY);
		break;
	case IWL_FMAC_CIPHER_WEP104:
	case IWL_FMAC_CIPHER_WEP40:
		new_key->iv_len = IEEE80211_WEP_IV_LEN;
		break;
	default:
		new_key->iv_len = 0;
		WARN_ON_ONCE(1);
	}

	for (q = 0; q < fmac->trans->num_rx_queues; q++)
		for (tid = 0; tid < IWL_MAX_TID_COUNT; tid++)
			memcpy(new_key->q[q].pn[tid], fw_key->rx_pn,
			       fw_key->rx_pn_len);

	if (pairwise) {
		struct iwl_fmac_sta_key *gtk_key;
		struct iwl_fmac_sta_key *key_tmp =
			rcu_dereference_protected(sta->ptk[fw_key->keyidx],
						  true);

		rcu_assign_pointer(sta->ptk[fw_key->keyidx], new_key);
		sta->ptk_idx = fw_key->keyidx;
		if (key_tmp)
			kfree_rcu(key_tmp, rcu_head);

		/*
		 * In WEP the same key is stored in both PTK and GTK arrays,
		 * prevent double free.
		 */
		gtk_key = rcu_dereference_protected(sta->gtk[fw_key->keyidx],
						    true);
		if (gtk_key == key_tmp)
			RCU_INIT_POINTER(sta->gtk[fw_key->keyidx], NULL);
	}

	if (!pairwise || new_key->cipher == IWL_FMAC_CIPHER_WEP40 ||
	    new_key->cipher == IWL_FMAC_CIPHER_WEP104) {
		struct iwl_fmac_sta_key *key_tmp =
			rcu_dereference_protected(sta->gtk[fw_key->keyidx],
						  true);

		rcu_assign_pointer(sta->gtk[fw_key->keyidx], new_key);
		sta->gtk_idx = fw_key->keyidx;
		if (key_tmp)
			kfree_rcu(key_tmp, rcu_head);
	}
}

static void
iwl_fmac_host_ap_sta_params(struct wiphy *wiphy, struct iwl_fmac_vif *vif,
			    const struct station_parameters *params,
			    const u8 *mac,
			    struct iwl_fmac_host_ap_sta_cmd *cmd)
{
	BUILD_BUG_ON(sizeof(cmd->ht_cap) != sizeof(*params->ht_capa));
	BUILD_BUG_ON(sizeof(cmd->vht_cap) != sizeof(*params->vht_capa));

	memcpy(cmd->addr, mac, sizeof(cmd->addr));

	if (params->ht_capa) {
		cmd->flags |= IWL_FMAC_STA_HT_CAPABLE;
		memcpy(cmd->ht_cap, params->ht_capa, sizeof(cmd->ht_cap));
		cmd->changed |= cpu_to_le16(IWL_FMAC_STA_HT_CAP_CHANGED);
	}

	if (params->vht_capa) {
		cmd->flags |= IWL_FMAC_STA_VHT_CAPABLE;
		memcpy(cmd->vht_cap, params->vht_capa, sizeof(cmd->vht_cap));
		cmd->changed |= cpu_to_le16(IWL_FMAC_STA_VHT_CAP_CHANGED);
	}

	if (params->sta_modify_mask & STATION_PARAM_APPLY_UAPSD) {
		if (params->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_BK)
			cmd->uapsd_ac |= BIT(AC_BK);
		if (params->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_BE)
			cmd->uapsd_ac |= BIT(AC_BE);
		if (params->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VI)
			cmd->uapsd_ac |= BIT(AC_VI);
		if (params->uapsd_queues & IEEE80211_WMM_IE_STA_QOSINFO_AC_VO)
			cmd->uapsd_ac |= BIT(AC_VO);
		if (params->uapsd_queues)
			cmd->sp_length =
				params->max_sp ? params->max_sp * 2 : 128;
		cmd->changed |= cpu_to_le16(IWL_FMAC_STA_UAPSD_PARAMS_CHANGED);
	}

	if (params->aid &&
	    params->sta_flags_mask & BIT(NL80211_STA_FLAG_ASSOCIATED) &&
	    params->sta_flags_set & BIT(NL80211_STA_FLAG_ASSOCIATED)) {
		cmd->aid = cpu_to_le16(params->aid);
		cmd->changed |= cpu_to_le16(IWL_FMAC_STA_AID_CHANGED);
	}

	if (params->supported_rates && params->supported_rates_len) {
		u16 supp_rates_bm =
			iwl_fmac_parse_rates(wiphy, vif,
					     params->supported_rates,
					     params->supported_rates_len);
		cmd->supp_rates_bitmap = cpu_to_le16(supp_rates_bm);
		cmd->changed |= cpu_to_le16(IWL_FMAC_STA_SUPP_RATE_CHANGED);
	}
}

static void
iwl_fmac_host_ap_check_sta_flags(struct iwl_fmac_sta *sta,
				 const struct station_parameters *params)
{
	u32 mask = params->sta_flags_mask;
	u32 set = params->sta_flags_set;

	if (mask & BIT(NL80211_STA_FLAG_WME))
		sta->qos = set & BIT(NL80211_STA_FLAG_WME);

	if (mask & BIT(NL80211_STA_FLAG_AUTHORIZED))
		sta->authorized = set & BIT(NL80211_STA_FLAG_AUTHORIZED);

	if (mask & BIT(NL80211_STA_FLAG_ASSOCIATED))
		sta->associated = set & BIT(NL80211_STA_FLAG_ASSOCIATED);
}

int iwl_fmac_host_ap_add_sta(struct wiphy *wiphy, struct net_device *dev,
			     const u8 *mac,
			     const struct station_parameters *params)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac_host_ap_sta_cmd cmd = {
		.action = IWL_FMAC_ADD_HOST_BASED_STA,
		.vif_id = vif->id,
	};
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(FMAC_HOST_BASED_AP_STA, FMAC_GROUP, 0),
		.data = { &cmd, },
		.len = { sizeof(cmd) },
	};
	struct iwl_fmac_sta *sta;
	u32 sta_id;
	int ret;

	lockdep_assert_held(&fmac->mutex);

	iwl_fmac_host_ap_sta_params(wiphy, vif, params, mac, &cmd);

	/* TODO: will be covered later */
	if (WARN_ON((params->sta_flags_mask & BIT(NL80211_STA_FLAG_MFP)) &&
		    (params->sta_flags_set  & BIT(NL80211_STA_FLAG_MFP))))
		return -EINVAL;

	ret = iwl_fmac_send_cmd_status(fmac, &hcmd, &sta_id);
	if (ret)
		return ret;

	if (sta_id == IWL_FMAC_HOST_AP_INVALID_STA)
		return -ENOSPC;

	ret = iwl_fmac_alloc_sta(fmac, vif, sta_id, mac);
	/*
	 * This will leave the firmware in an inconsistent state, but
	 * there isn't much we can do here.
	 */
	if (ret)
		return ret;

	sta = rcu_dereference_protected(fmac->stas[sta_id],
					lockdep_is_held(&fmac->mutex));

	if (WARN_ON(IS_ERR_OR_NULL(sta)))
		return -EINVAL;

	iwl_fmac_host_ap_check_sta_flags(sta, params);

	return 0;
}

int iwl_fmac_host_ap_mod_sta(struct wiphy *wiphy, struct net_device *dev,
			     const u8 *mac,
			     const struct station_parameters *params)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac_host_ap_sta_cmd cmd = {
		.action = IWL_FMAC_MOD_HOST_BASED_STA,
		.vif_id = vif->id,
	};
	struct iwl_fmac_sta *sta;
	int ret;

	lockdep_assert_held(&fmac->mutex);

	sta = iwl_get_sta(fmac, mac);
	if (!sta) {
		IWL_ERR(fmac, "Couldn't find station %pM\n", mac);
		return -ENOENT;
	}
	cmd.sta_id = sta->sta_id;

	/* TODO: will be covered later */
	if (WARN_ON((params->sta_flags_mask & BIT(NL80211_STA_FLAG_MFP)) &&
		    (params->sta_flags_set  & BIT(NL80211_STA_FLAG_MFP))))
		return -EINVAL;

	iwl_fmac_host_ap_sta_params(wiphy, vif, params, mac, &cmd);

	ret = iwl_fmac_send_cmd_pdu(fmac, iwl_cmd_id(FMAC_HOST_BASED_AP_STA,
						     FMAC_GROUP, 0), 0,
				    sizeof(cmd), &cmd);
	if (ret)
		return ret;

	iwl_fmac_host_ap_check_sta_flags(sta, params);

	return 0;
}

void iwl_fmac_host_ap_del_sta(struct iwl_fmac *fmac, struct iwl_fmac_vif *vif,
			      struct iwl_fmac_sta *sta)
{
	lockdep_assert_held(&fmac->mutex);


	/*
	 * Even if we couldn't remove the station from the firwmare, we should
	 * still clean up our own memory. We set fmac->stas[] to NULL so that
	 * we won't pass any further frame for that station to the netstack.
	 */

	RCU_INIT_POINTER(fmac->stas[sta->sta_id], NULL);

	synchronize_net();

	iwl_fmac_destroy_sta(fmac, sta, false);
}

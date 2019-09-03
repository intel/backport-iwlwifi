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
#include <linux/netdevice.h>
#include <uapi/linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <net/ieee80211_radiotap.h>
#include <crypto/algapi.h>

#include "iwl-trans.h"
#include "fmac.h"
#include "fw/api/rx.h"
#include "fw/api/fmac.h"

/* data for all parts of the RX path */
struct rx_data {
	struct iwl_fmac_sta *sta;
	struct iwl_fmac_vif *vif;
	struct napi_struct *napi;
	int queue;
};

/* data stored with each SKB (in the CB) */
struct rx_skb_data {
	bool allow_same_pn;
};

/*
 * data needed before we have an SKB, not used afterwards
 * (after the SKB has passed through the reorder buffer)
 */
struct rx_preskb_data {
	struct iwl_rx_mpdu_desc *desc;
	struct iwl_rx_cmd_buffer *rxb;
	u16 len;
	u8 crypt_len;
	bool mmic_failure;

	/* before building the SKB, start here */
	struct rx_skb_data skb_data;
};

static inline struct rx_skb_data *skb_get_data(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct rx_skb_data) > sizeof(skb->cb));

	return (void *)skb->cb;
}

/* Defined later on below */
static void iwl_fmac_prepare_and_deliver_skb(struct iwl_fmac *fmac,
					     struct rx_data *rx,
					     struct sk_buff *skb,
					     bool mmic_failure);

static bool iwl_fmac_accept_frame(struct iwl_fmac *fmac,
				  struct ieee80211_hdr *hdr,
				  struct rx_data *rx)
{
	bool mcast = is_multicast_ether_addr(hdr->addr1);
	__le16 fc = hdr->frame_control;

	/* we don't support a4 packets */
	if (ieee80211_has_a4(fc))
		return false;

	switch (rx->vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
		if (!ieee80211_has_fromds(fc))
			return false;
		return mcast || ether_addr_equal(rx->vif->addr, hdr->addr1);
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		if (!ieee80211_has_tods(fc))
			return false;
		return mcast || ether_addr_equal(rx->vif->addr, hdr->addr1);
	default:
		WARN(1, "iftype not supported %d\n",
		     rx->vif->wdev.iftype);
		return false;
	};
}

static int iwl_fmac_get_signal_mbm(struct iwl_fmac *fmac,
				   struct iwl_rx_mpdu_desc *desc)
{
	bool v3 = fmac->trans->cfg->device_family >= IWL_DEVICE_FAMILY_22560;
	int energy_a = (v3) ? desc->v3.energy_a : desc->v1.energy_a;
	int energy_b = (v3) ? desc->v3.energy_b : desc->v1.energy_b;

	energy_a = energy_a ? -energy_a : S8_MIN;
	energy_b = energy_b ? -energy_b : S8_MIN;

	return DBM_TO_MBM(max(energy_a, energy_b));
}

/*
 * returns true if a packet is a duplicate and should be dropped.
 * Updates AMSDU PN tracking info
 */
static bool iwl_fmac_is_dup(struct iwl_fmac *fmac,
			    struct ieee80211_hdr *hdr,
			    struct rx_data *rx,
			    struct rx_preskb_data *preskb)
{
	struct iwl_fmac_rxq_dup_data *dup_data;
	struct iwl_fmac_sta *sta = rx->sta;
	u8 tid, sub_frame_idx, mac_flags2, amsdu_info;

	if (WARN_ON(IS_ERR_OR_NULL(sta)))
		return false;

	dup_data = &sta->dup_data[rx->queue];
	mac_flags2 = preskb->desc->mac_flags2;
	amsdu_info = preskb->desc->amsdu_info;
	/*
	 * Drop duplicate 802.11 retransmissions
	 * (IEEE 802.11-2012: 9.3.2.10 "Duplicate detection and recovery")
	 */
	if (is_multicast_ether_addr(hdr->addr1))
		return false;

	if (ieee80211_is_data_qos(hdr->frame_control))
		/* frame has qos control */
		tid = *ieee80211_get_qos_ctl(hdr) &
			IEEE80211_QOS_CTL_TID_MASK;
	else
		tid = IWL_MAX_TID_COUNT;

	/* If this wasn't a part of an A-MSDU the sub-frame index will be 0 */
	sub_frame_idx = amsdu_info & IWL_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK;

	if (unlikely(ieee80211_has_retry(hdr->frame_control) &&
		     dup_data->last_seq[tid] == hdr->seq_ctrl &&
		     dup_data->last_sub_frame[tid] >= sub_frame_idx))
		return true;

	/* Allow same PN as the first subframe for following sub frames */
	if (dup_data->last_seq[tid] == hdr->seq_ctrl &&
	    sub_frame_idx > dup_data->last_sub_frame[tid] &&
	    mac_flags2 & IWL_RX_MPDU_MFLG2_AMSDU)
		preskb->skb_data.allow_same_pn = true;

	dup_data->last_seq[tid] = hdr->seq_ctrl;
	dup_data->last_sub_frame[tid] = sub_frame_idx;

	return false;
}

/*
 * Returns true if sn2 - buffer_size < sn1 < sn2.
 * To be used only in order to compare reorder buffer head with NSSN.
 * We fully trust NSSN unless it is behind us due to reorder timeout.
 * Reorder timeout can only bring us up to buffer_size SNs ahead of NSSN.
 */
static bool iwl_fmac_is_sn_less(u16 sn1, u16 sn2, u16 buffer_size)
{
	return ieee80211_sn_less(sn1, sn2) &&
	       !ieee80211_sn_less(sn1, sn2 - buffer_size);
}

#define RX_REORDER_BUF_TIMEOUT_MQ (HZ / 10)

static void iwl_fmac_release_frames(struct iwl_fmac *fmac,
				    struct iwl_fmac_reorder_buffer *reorder_buf,
				    struct rx_data *rx,
				    u16 nssn)
{
	u16 ssn = reorder_buf->head_sn;

	lockdep_assert_held(&reorder_buf->lock);

	/* ignore nssn smaller than head sn - this can happen due to timeout */
	if (iwl_fmac_is_sn_less(nssn, ssn, reorder_buf->buf_size))
		goto set_timer;

	while (iwl_fmac_is_sn_less(ssn, nssn, reorder_buf->buf_size)) {
		int index = ssn % reorder_buf->buf_size;
		struct sk_buff_head *skb_list = &reorder_buf->entries[index];
		struct sk_buff *skb;

		ssn = ieee80211_sn_inc(ssn);

		/*
		 * Empty the list. Will have more than one frame for A-MSDU.
		 * Empty list is valid as well since nssn indicates frames were
		 * received.
		 */
		while ((skb = __skb_dequeue(skb_list))) {
			iwl_fmac_prepare_and_deliver_skb(fmac, rx, skb, false);
			reorder_buf->num_stored--;
		}
	}
	reorder_buf->head_sn = nssn;

set_timer:
	if (reorder_buf->num_stored && reorder_buf->sta_id < IWL_FMAC_MAX_STA) {
		u16 index = reorder_buf->head_sn % reorder_buf->buf_size;

		while (skb_queue_empty(&reorder_buf->entries[index]))
			index = (index + 1) % reorder_buf->buf_size;
		/* modify timer to match next frame's expiration time */
		mod_timer(&reorder_buf->reorder_timer,
			  reorder_buf->reorder_time[index] + 1 +
			  RX_REORDER_BUF_TIMEOUT_MQ);
	} else {
		del_timer(&reorder_buf->reorder_timer);
	}
}

static void iwl_fmac_reorder_timer_expired(struct timer_list *t)
{
	struct iwl_fmac_reorder_buffer *buf = from_timer(buf, t, reorder_timer);
	int i;
	u16 sn = 0, index = 0;
	bool expired = false;
	bool cont = false;

	spin_lock(&buf->lock);

	if (!buf->num_stored || buf->sta_id >= IWL_FMAC_MAX_STA) {
		spin_unlock(&buf->lock);
		return;
	}

	for (i = 0; i < buf->buf_size ; i++) {
		index = (buf->head_sn + i) % buf->buf_size;

		if (skb_queue_empty(&buf->entries[index])) {
			/*
			 * If there is a hole and the next frame didn't expire
			 * we want to break and not advance SN
			 */
			cont = false;
			continue;
		}
		if (!cont && !time_after(jiffies, buf->reorder_time[index] +
					 RX_REORDER_BUF_TIMEOUT_MQ))
			break;

		expired = true;
		/* continue until next hole after this expired frames */
		cont = true;
		sn = ieee80211_sn_add(buf->head_sn, i + 1);
	}

	if (expired) {
		struct iwl_fmac_sta *sta;
		struct rx_data rx = {};

		rcu_read_lock();
		sta = rcu_dereference(buf->fmac->stas[buf->sta_id]);
		/* SN is set to the last expired frame + 1 */
		IWL_DEBUG_HT(buf->fmac,
			     "Releasing expired frames for sta %u, sn %d\n",
			     buf->sta_id, sn);

		rx.vif = sta->vif;
		rx.sta = sta;
		rx.queue = buf->queue;
		rx.napi = NULL;

		iwl_fmac_release_frames(buf->fmac, buf, &rx, sn);
		rcu_read_unlock();
	} else {
		/*
		 * If no frame expired and there are stored frames, index is now
		 * pointing to the first unexpired frame - modify timer
		 * accordingly to this frame.
		 */
		mod_timer(&buf->reorder_timer,
			  buf->reorder_time[index] +
			  1 + RX_REORDER_BUF_TIMEOUT_MQ);
	}
	spin_unlock(&buf->lock);
}

static void iwl_fmac_init_reorder_buffer(struct iwl_fmac_reorder_buffer *buf,
					 struct iwl_fmac_sta *sta, u16 ssn,
					 u8 buf_size, int queue)
{
	int j;

	buf->num_stored = 0;
	buf->head_sn = ssn;
	buf->buf_size = buf_size;
	/* rx reorder timer */
	timer_setup(&buf->reorder_timer, iwl_fmac_reorder_timer_expired, 0);
	spin_lock_init(&buf->lock);
	buf->queue = queue;
	buf->sta_id = sta->sta_id;
	for (j = 0; j < buf->buf_size; j++)
		__skb_queue_head_init(&buf->entries[j]);
}

void iwl_fmac_destroy_reorder_buffer(struct iwl_fmac *fmac,
				     struct iwl_fmac_sta *sta,
				     struct iwl_fmac_reorder_buffer *buf)
{
	struct rx_data rx = {
		.vif = sta->vif,
		.sta = sta,
		.queue = buf->queue,
	};

	if (buf->sta_id == IWL_FMAC_INVALID_STA_ID)
		return;

	spin_lock_bh(&buf->lock);
	iwl_fmac_release_frames(fmac, buf, &rx,
				ieee80211_sn_add(buf->head_sn, buf->buf_size));
	buf->sta_id = IWL_FMAC_INVALID_STA_ID;
	spin_unlock_bh(&buf->lock);

	del_timer_sync(&buf->reorder_timer);
}

static bool iwl_fmac_reorder(struct iwl_fmac *fmac, struct rx_data *rx,
			     struct rx_preskb_data *preskb, struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	u32 reorder = le32_to_cpu(preskb->desc->reorder_data);
	struct iwl_fmac_reorder_buffer *buffer;
	struct sk_buff *tail;
	u8 amsdu_info = preskb->desc->amsdu_info;
	bool last_subframe = amsdu_info & IWL_RX_MPDU_AMSDU_LAST_SUBFRAME;
	u8 sub_frame_idx = amsdu_info &
			   IWL_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK;
	bool amsdu = preskb->desc->mac_flags2 & IWL_RX_MPDU_MFLG2_AMSDU;
	u16 nssn, sn, min_sn;
	int index;
	u8 baid;

	baid = (reorder & IWL_RX_MPDU_REORDER_BAID_MASK) >>
		IWL_RX_MPDU_REORDER_BAID_SHIFT;

	if (baid >= IWL_MAX_BAID)
		return false;

	/* no sta yet */
	if (WARN_ON(IS_ERR_OR_NULL(rx->sta)))
		return false;

	/* not a data packet */
	if (!ieee80211_is_data_qos(hdr->frame_control) ||
	    is_multicast_ether_addr(hdr->addr1))
		return false;

	if (unlikely(!ieee80211_is_data_present(hdr->frame_control)))
		return false;

	nssn = reorder & IWL_RX_MPDU_REORDER_NSSN_MASK;
	sn = (reorder & IWL_RX_MPDU_REORDER_SN_MASK) >>
		IWL_RX_MPDU_REORDER_SN_SHIFT;
	min_sn = ieee80211_sn_less(sn, nssn) ? sn : nssn;

	/* Check if buffer needs to be initialized */
	buffer = &fmac->reorder_bufs[baid][rx->queue];
	if (buffer->sta_id == IWL_FMAC_INVALID_STA_ID) {
		/* don't initialize until first valid packet comes through */
		if (reorder & IWL_RX_MPDU_REORDER_BA_OLD_SN)
			return false;
		iwl_fmac_init_reorder_buffer(buffer, rx->sta, min_sn,
					     IEEE80211_MAX_AMPDU_BUF_HT,
					     rx->queue);
	}

	spin_lock_bh(&buffer->lock);

	/*
	 * If there was a significant jump in the nssn - adjust.
	 * If the SN is smaller than the NSSN it might need to first go into
	 * the reorder buffer, in which case we just release up to it and the
	 * rest of the function will take care of storing it and releasing up to
	 * the nssn
	 */
	if (!iwl_fmac_is_sn_less(nssn, buffer->head_sn + buffer->buf_size,
				 buffer->buf_size) ||
	    !ieee80211_sn_less(sn, buffer->head_sn + buffer->buf_size))
		iwl_fmac_release_frames(buffer->fmac, buffer, rx, min_sn);

	/* drop any oudated packets */
	if (ieee80211_sn_less(sn, buffer->head_sn))
		goto drop;

	/* release immediately if allowed by nssn and no stored frames */
	if (!buffer->num_stored && ieee80211_sn_less(sn, nssn)) {
		if (iwl_fmac_is_sn_less(buffer->head_sn, nssn,
					buffer->buf_size) &&
		   (!amsdu || last_subframe))
			buffer->head_sn = nssn;
		/* No need to update AMSDU last SN - we are moving the head */
		spin_unlock_bh(&buffer->lock);
		return false;
	}

	index = sn % buffer->buf_size;

	/*
	 * Check if we already stored this frame
	 * As AMSDU is either received or not as whole, logic is simple:
	 * If we have frames in that position in the buffer and the last frame
	 * originated from AMSDU had a different SN then it is a retransmission.
	 * If it is the same SN then if the subframe index is incrementing it
	 * is the same AMSDU - otherwise it is a retransmission.
	 */
	tail = skb_peek_tail(&buffer->entries[index]);
	if (tail && !amsdu)
		goto drop;
	else if (tail && (sn != buffer->last_amsdu ||
			  buffer->last_sub_index >= sub_frame_idx))
		goto drop;

	/* put in reorder buffer */
	__skb_queue_tail(&buffer->entries[index], skb);
	buffer->num_stored++;
	buffer->reorder_time[index] = jiffies;

	if (amsdu) {
		buffer->last_amsdu = sn;
		buffer->last_sub_index = sub_frame_idx;
	}

	/*
	 * We cannot trust NSSN for AMSDU sub-frames that are not the last.
	 * The reason is that NSSN advances on the first sub-frame, and may
	 * cause the reorder buffer to advance before all the sub-frames arrive.
	 * Example: reorder buffer contains SN 0 & 2, and we receive AMSDU with
	 * SN 1. NSSN for first sub frame will be 3 with the result of driver
	 * releasing SN 0,1, 2. When sub-frame 1 arrives - reorder buffer is
	 * already ahead and it will be dropped.
	 * If the last sub-frame is not on this queue - we will get frame
	 * release notification with up to date NSSN.
	 */
	if (!amsdu || last_subframe)
		iwl_fmac_release_frames(buffer->fmac, buffer, rx, nssn);

	spin_unlock_bh(&buffer->lock);

	return true;

drop:
	spin_unlock_bh(&buffer->lock);
	kfree_skb(skb);

	return true;
}

/* iwl_fmac_create_skb Adds the rxb to a new skb */
static void iwl_fmac_create_skb(struct iwl_fmac *fmac,
				struct rx_preskb_data *preskb,
				struct sk_buff *skb,
				void *hdr,
				unsigned int hdrlen)
{
	unsigned int headlen, fraglen, pad_len = 0;
	u16 len = preskb->len;
	u8 mac_flags2 = preskb->desc->mac_flags2;

	if (mac_flags2 & IWL_RX_MPDU_MFLG2_PAD) {
		pad_len = 2;

		/*
		 * If the device inserted padding it means that (it thought)
		 * the 802.11 header wasn't a multiple of 4 bytes long. In
		 * this case, reserve two bytes at the start of the SKB to
		 * align the payload properly in case we end up copying it.
		 */
		skb_reserve(skb, pad_len);
	}
	len -= pad_len;

	/* If frame is small enough to fit in skb->head, pull it completely.
	 * If not, only pull ieee80211_hdr (including crypto if present, and
	 * an additional 8 bytes for SNAP/ethertype, see below) so that
	 * splice() or TCP coalesce are more efficient.
	 *
	 * Since, in addition, ieee80211_data_to_8023() always pull in at
	 * least 8 bytes (possibly more for mesh) we can do the same here
	 * to save the cost of doing it later. That still doesn't pull in
	 * the actual IP header since the typical case has a SNAP header.
	 * If the latter changes (there are efforts in the standards group
	 * to do so) we should revisit this and ieee80211_data_to_8023().
	 */
	headlen = (len <= skb_tailroom(skb)) ? len :
					       hdrlen + preskb->crypt_len + 8;

	/* The firmware may align the packet to DWORD.
	 * The padding is inserted after the IV.
	 * After copying the header + IV skip the padding if
	 * present before copying packet data.
	 */
	hdrlen += preskb->crypt_len;
	memcpy(skb_put(skb, hdrlen), hdr, hdrlen);
	memcpy(skb_put(skb, headlen - hdrlen), (u8 *)hdr + hdrlen + pad_len,
	       headlen - hdrlen);

	fraglen = len - headlen;

	if (fraglen) {
		int offset = hdr + headlen + pad_len -
			     rxb_addr(preskb->rxb) + rxb_offset(preskb->rxb);

		skb_add_rx_frag(skb, 0, rxb_steal_page(preskb->rxb), offset,
				fraglen, preskb->rxb->truesize);
	}

	memcpy(skb->cb, &preskb->skb_data, sizeof(preskb->skb_data));
}

static bool iwl_fmac_rx_drop_unencrypted(struct iwl_fmac *fmac,
					 struct ieee80211_hdr *hdr,
					 struct rx_data *rx)
{
	/* TODO: check for EAPOL frames for 1X */
	return rx->sta->encryption;
}

static bool iwl_fmac_accept_rx_crypto(struct iwl_fmac *fmac,
				      struct rx_data *rx,
				      struct rx_preskb_data *preskb)
{
	u16 status = le16_to_cpu(preskb->desc->status);

	switch (status & IWL_RX_MPDU_STATUS_SEC_MASK) {
	case IWL_RX_MPDU_STATUS_SEC_CCM:
	case IWL_RX_MPDU_STATUS_SEC_GCM:
		BUILD_BUG_ON(IEEE80211_CCMP_PN_LEN != IEEE80211_GCMP_PN_LEN);
		/* alg is CCM: check MIC only */
		if (!(status & IWL_RX_MPDU_STATUS_MIC_OK))
			return false;

		preskb->crypt_len = IEEE80211_CCMP_HDR_LEN;
		return true;
	case IWL_RX_MPDU_STATUS_SEC_TKIP:
		if (fmac->trans->cfg->gen2)
			preskb->mmic_failure =
				!(status & RX_MPDU_RES_STATUS_MIC_OK);
		else
			preskb->mmic_failure = 0;

		preskb->crypt_len = IEEE80211_TKIP_IV_LEN;
		/* fall through */
	case IWL_RX_MPDU_STATUS_SEC_WEP:
		if (!(status & IWL_RX_MPDU_STATUS_ICV_OK))
			return false;

		if ((status & IWL_RX_MPDU_STATUS_SEC_MASK) ==
				IWL_RX_MPDU_STATUS_SEC_WEP)
			preskb->crypt_len = IEEE80211_WEP_IV_LEN;
		return true;
	case IWL_RX_MPDU_STATUS_SEC_EXT_ENC:
		if (!(status & IWL_RX_MPDU_STATUS_MIC_OK))
			return false;
		return true;
	default:
		IWL_ERR(fmac, "Unhandled alg: 0x%x\n", status);
		return false;
	}

	return true;
}

static bool iwl_fmac_remove_wep_iv(struct iwl_fmac *fmac,
				   struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;

	memmove(skb->data + IEEE80211_WEP_IV_LEN, skb->data,
		ieee80211_hdrlen(hdr->frame_control));
	return skb_pull(skb, IEEE80211_WEP_IV_LEN) ? true : false;
}

static bool iwl_fmac_accept_ccm_gcm_pn(struct iwl_fmac *fmac,
				       struct rx_data *rx,
				       struct iwl_fmac_sta_key *key,
				       struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	u8 *extiv = (u8 *)hdr + ieee80211_hdrlen(hdr->frame_control);
	u8 pn[IEEE80211_CCMP_PN_LEN], tid;
	int res;

	if (ieee80211_is_data_qos(hdr->frame_control))
		tid = *ieee80211_get_qos_ctl(hdr) & IEEE80211_QOS_CTL_TID_MASK;
	else
		tid = 0;

	/* we don't use HCCA/802.11 QoS TSPECs, so drop such frames */
	if (tid >= IWL_MAX_TID_COUNT)
		return false;

	pn[0] = extiv[7];
	pn[1] = extiv[6];
	pn[2] = extiv[5];
	pn[3] = extiv[4];
	pn[4] = extiv[1];
	pn[5] = extiv[0];

	res = memcmp(pn, key->q[rx->queue].pn[tid], IEEE80211_CCMP_PN_LEN);
	if (res < 0)
		return false;
	if (!res && !skb_get_data(skb)->allow_same_pn)
		return false;

	memcpy(key->q[rx->queue].pn[tid], pn, IEEE80211_CCMP_PN_LEN);

	/* don't check if we can trim since we have one single fragment that
	 * is long enough.
	 */
	memmove(skb->data + IEEE80211_CCMP_HDR_LEN, skb->data,
		ieee80211_hdrlen(hdr->frame_control));
	skb_pull(skb, IEEE80211_CCMP_HDR_LEN);

	return true;
}

#ifdef CPTCFG_IWLFMAC_9000_SUPPORT

#define MICHAEL_MIC_LEN 8

/*
 * iwl_fmac_michael_block - Compute the michael block
 *
 * @ctx: the mic context, i.e., (l, r)
 * @b: the message word that michael needs to be applied to.
 *
 * See IEEE80211-2016, section 12.5.2.3.3
 */
static void iwl_fmac_michael_block(u32 ctx[2], u32 b)
{
	ctx[0] ^= b;
	ctx[1] ^= rol32(ctx[0], 17);
	ctx[0] += ctx[1];
	ctx[1] ^= ((ctx[0] & 0xff00ff00) >> 8) | ((ctx[0] & 0x00ff00ff) << 8);
	ctx[0] += ctx[1];
	ctx[1] ^= rol32(ctx[0], 3);
	ctx[0] += ctx[1];
	ctx[1] ^= ror32(ctx[0], 2);
	ctx[0] += ctx[1];
}

/*
 * iwl_fmac_michael_mic_init - Michael initialization
 *
 * @ctx: the mic context, i.e., (l, r)
 * @key: the key
 * @da: the MSDU's destination address
 * @sa: the MSDU's source address
 * @tid: the MSDU's traffic TID
 *
 * See IEEE80211-2016, section 12.5.2.3.3
 */
static void iwl_fmac_michael_mic_init(u32 ctx[2], const u8 *key,
				      const u8 *da, const u8 *sa,
				      u8 tid)
{
	/* Initialize the MIC with the given key */
	ctx[0] = get_unaligned_le32(key);
	ctx[1] = get_unaligned_le32(key + 4);

	/*
	 * And then compute the initialization header:
	 * DA + SA + TID + (0, 0, 0)
	 */
	iwl_fmac_michael_block(ctx, get_unaligned_le32(da));
	iwl_fmac_michael_block(ctx, get_unaligned_le16(&da[4]) |
			       (get_unaligned_le16(sa) << 16));
	iwl_fmac_michael_block(ctx, get_unaligned_le32(&sa[2]));
	iwl_fmac_michael_block(ctx, tid);
}

/*
 * iwl_fmac_michael_mic - Compute the michael mic
 *
 * @key: the michael key
 * @hdr: the MSDU's header
 * @data: the MSDU's data
 * @data_len: the data length
 * @mic: On return would hold the computed mic
 */
static void iwl_fmac_michael_mic(const u8 *key, struct ieee80211_hdr *hdr,
				 const u8 *data, size_t data_len, u8 *mic)
{
	u32 ctx[2], val;
	size_t n_blocks, left, i;
	u8 *da, *sa, tid;

	/* Perform MIC initialization using the key and header information */
	da = ieee80211_get_DA(hdr);
	sa = ieee80211_get_SA(hdr);
	if (ieee80211_is_data_qos(hdr->frame_control))
		tid = ieee80211_get_tid(hdr);
	else
		tid = 0;

	iwl_fmac_michael_mic_init(ctx, key, da, sa, tid);

	/*
	 * the michael block operates on 4 octets, so the MDSU data needs to
	 * be split to 4 octet blocks. The bytes that are left are padded with a
	 * single byte of 0x5 followed by zeros.
	 */
	n_blocks = data_len / 4;
	left = data_len % 4;

	for (i = 0; i < n_blocks; i++)
		iwl_fmac_michael_block(ctx, get_unaligned_le32(&data[i * 4]));

	/* if needed, create the block with the bytes left and the padding */
	val = 0x5a;
	while (left > 0) {
		val <<= 8;
		left--;
		val |= data[n_blocks * 4 + left];
	}
	iwl_fmac_michael_block(ctx, val);

	/* last block is always 0 */
	iwl_fmac_michael_block(ctx, 0);

	put_unaligned_le32(ctx[0], mic);
	put_unaligned_le32(ctx[1], mic + 4);
}

static bool iwl_fmac_accept_tkip_tsc(struct iwl_fmac *fmac,
				     struct rx_data *rx,
				     struct iwl_fmac_sta_key *key,
				     struct sk_buff *skb,
				     bool mmic_failure)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	u8 *iv = (u8 *)hdr + ieee80211_hdrlen(hdr->frame_control);
	u8 tid;
	u16 iv16 = (iv[0] << 8) | iv[2];
	u32 iv32 = get_unaligned_le32(iv + 4);

	if (ieee80211_is_data_qos(hdr->frame_control))
		tid = *ieee80211_get_qos_ctl(hdr) & IEEE80211_QOS_CTL_TID_MASK;
	else
		tid = 0;

	if (iv32 < key->q[rx->queue].tsc[tid].iv32 ||
	    (iv32 == key->q[rx->queue].tsc[tid].iv32 &&
	     iv16 <= key->q[rx->queue].tsc[tid].iv16))
		return false;

	if (!fmac->trans->cfg->gen2) {
#ifdef CPTCFG_IWLFMAC_9000_SUPPORT
		u8 mic[MICHAEL_MIC_LEN];
		unsigned int hdrlen;
		u8 *data;
		size_t data_len;

		/*
		 * TKIP for non gen2 devices is only supported for multicast
		 * frames.
		 */
		if (!is_multicast_ether_addr(hdr->addr1))
			return false;

		hdrlen = ieee80211_hdrlen(hdr->frame_control);

		/* Need to linearize before MIC verification */
		if (skb_linearize(skb))
			return false;

		hdr = (struct ieee80211_hdr *)skb->data;
		data = skb->data + hdrlen + IEEE80211_TKIP_IV_LEN;
		data_len = skb->len - hdrlen - MICHAEL_MIC_LEN -
			IEEE80211_TKIP_IV_LEN;

		iwl_fmac_michael_mic(key->tkip_mcast_rx_mic_key,
				     hdr, data, data_len, mic);

		if (crypto_memneq(mic, data + data_len, MICHAEL_MIC_LEN))
			mmic_failure = true;
		else
			skb_trim(skb, skb->len - MICHAEL_MIC_LEN);

		if (key->q[rx->queue].tsc[tid].iv32 != iv32) {
			struct iwl_fmac_tkip_mcast_rsc cmd = {
				.vif_id = rx->vif->id,
				.key_idx = key->keyidx,
			};

			memcpy(cmd.addr, rx->sta->addr, ETH_ALEN);
			*((__le32 *)cmd.rsc) = cpu_to_le32(iv32);
			*((__le16 *)(cmd.rsc + sizeof(iv32))) =
				cpu_to_le16(iv16);

			mutex_lock(&fmac->mutex);
			iwl_fmac_send_cmd_pdu(fmac,
					      iwl_cmd_id(FMAC_TKIP_SET_MCAST_RSC,
							 FMAC_GROUP,
							 0),
					      CMD_ASYNC, sizeof(cmd), &cmd);
			mutex_unlock(&fmac->mutex);
		}
#else
		WARN(1, "TKIP MIC supported only with 9000 devices");
		mmic_failure = true;
#endif /* CPTCFG_IWLFMAC_9000_SUPPORT */
	}

	if (mmic_failure) {
		struct iwl_fmac_mic_failure cmd = {
			.vif_id = rx->vif->id,
			.pairwise = !is_multicast_ether_addr(hdr->addr1)
		};

		mutex_lock(&fmac->mutex);
		iwl_fmac_send_cmd_pdu(fmac,
				      iwl_cmd_id(FMAC_MIC_FAILURE, FMAC_GROUP,
						 0),
				      CMD_ASYNC, sizeof(cmd), &cmd);
		mutex_unlock(&fmac->mutex);

		return false;
	}

	key->q[rx->queue].tsc[tid].iv32 = iv32;
	key->q[rx->queue].tsc[tid].iv16 = iv16;

	memmove(skb->data + IEEE80211_TKIP_IV_LEN, skb->data,
		ieee80211_hdrlen(hdr->frame_control));
	skb_pull(skb, IEEE80211_TKIP_IV_LEN);

	return true;
}
#endif /* CPTCFG_IWLFMAC_9000_SUPPORT */

static bool iwl_fmac_rx_crypto_skb(struct iwl_fmac *fmac, struct rx_data *rx,
				   struct sk_buff *skb, bool mmic_failure)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	struct iwl_fmac_sta_key *key;
	u8 keyidx, *extiv;

	/* No encryption => no PN check */
	if (!ieee80211_has_protected(hdr->frame_control))
		return true;

	/* We already pulled the IV */
	extiv = (u8 *)hdr + ieee80211_hdrlen(hdr->frame_control);
	keyidx = extiv[3] >> 6;

	if (unlikely(is_multicast_ether_addr(hdr->addr1)))
		key = rcu_dereference(rx->sta->gtk[keyidx]);
	else
		key = rcu_dereference(rx->sta->ptk[keyidx]);

	/* The frame is protected, but we can't find a key to check
	 * the PN... drop the packet. This can happen when we just
	 * removed the key.
	 */
	if (!key)
		return false;

	/* TODO: add PN check for more ciphers */
	switch (key->cipher) {
	case IWL_FMAC_CIPHER_WEP40:
	case IWL_FMAC_CIPHER_WEP104:
		return iwl_fmac_remove_wep_iv(fmac, skb);
	case IWL_FMAC_CIPHER_CCMP:
	case IWL_FMAC_CIPHER_CCMP_256:
	case IWL_FMAC_CIPHER_GCMP:
	case IWL_FMAC_CIPHER_GCMP_256:
		return iwl_fmac_accept_ccm_gcm_pn(fmac, rx, key, skb);
	case IWL_FMAC_CIPHER_TKIP:
		return iwl_fmac_accept_tkip_tsc(fmac, rx, key, skb,
						mmic_failure);
	default:
		IWL_ERR(fmac, "PN check not implemented for cipher %x\n",
			key->cipher);
		return true;
	}
}

/* returns true if frame should be passed to upper stack */
static bool iwl_fmac_forward_frames(struct iwl_fmac *fmac, struct rx_data *rx,
				    struct sk_buff *skb)
{
	struct sk_buff *out_skb = NULL;

	if ((rx->vif->wdev.iftype != NL80211_IFTYPE_AP &&
	     rx->vif->wdev.iftype != NL80211_IFTYPE_P2P_GO) ||
	    rx->vif->u.ap.isolate)
		return true;

	if (is_multicast_ether_addr(skb->data)) {
		/* multicast to both */
		out_skb = skb_copy(skb, GFP_ATOMIC);
	} else {
		struct iwl_fmac_sta *dest;

		/* redirect unicast if we know the station */
		dest = iwl_get_sta(fmac, skb->data);
		if (dest) {
			out_skb = skb;
			skb = NULL;
		}
	}

	if (out_skb) {
		out_skb->priority += 256;
		out_skb->protocol = htons(ETH_P_802_3);
		skb_reset_network_header(out_skb);
		skb_reset_mac_header(out_skb);
		out_skb->dev = rx->vif->wdev.netdev;
		dev_queue_xmit(out_skb);
	}

	return !!skb;
}

static bool iwl_fmac_rx_control_port_check(struct rx_data *rx,
					   struct sk_buff *skb)
{
	struct ethhdr *ethhdr = (void *)skb->data;

	if (rx->sta->authorized)
		return true;

	if (ethhdr->h_proto == rx->vif->control_port_ethertype)
		return true;

	kfree_skb(skb);
	return false;
}

static void iwl_fmac_prepare_and_deliver_skb(struct iwl_fmac *fmac,
					     struct rx_data *rx,
					     struct sk_buff *skb,
					     bool mmic_failure)
{
	if (!iwl_fmac_rx_crypto_skb(fmac, rx, skb, mmic_failure)) {
		kfree_skb(skb);
		return;
	}

	ieee80211_data_to_8023(skb, rx->vif->addr, rx->vif->wdev.iftype);

	if (!iwl_fmac_rx_control_port_check(rx, skb))
		return;

	/* forward to internal stations if needed */
	if (!iwl_fmac_forward_frames(fmac, rx, skb))
		return;

	skb->protocol = eth_type_trans(skb, rx->vif->wdev.netdev);
	if (rx->napi)
		napi_gro_receive(rx->napi, skb);
	else
		netif_receive_skb(skb);
}

static bool iwl_fmac_accept_eth_frame(struct iwl_fmac *fmac,
				      struct ethhdr *hdr,
				      struct rx_data *rx)
{
	bool mcast = is_multicast_ether_addr(hdr->h_dest);

	switch (rx->vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		return mcast || ether_addr_equal(rx->vif->addr, hdr->h_dest);
	default:
		WARN(1, "iftype not supported %d\n", rx->vif->wdev.iftype);
	return false;
	};
}

/* iwl_fmac_create_eth_skb Adds the rxb to a new skb */
static void iwl_fmac_create_eth_skb(struct iwl_fmac *fmac,
				    struct rx_preskb_data *preskb,
				    struct sk_buff *skb,
				    struct ethhdr *hdr)
{
	unsigned int fraglen;
	u16 len = preskb->len;
	int headlen = sizeof(*hdr);

	/* align the skb, so L3 start will be aligned */
	skb_reserve(skb, headlen & 3);

	/*
	 * If frame is small enough to fit in skb->head, pull it completely.
	 * If not, only pull ethhdr so that splice() or TCP coalesce are more
	 * efficient.
	 */
	headlen = (len <= skb_tailroom(skb)) ? len : headlen;
	skb_put_data(skb, hdr, headlen);

	fraglen = len - headlen;
	if (fraglen) {
		int offset = (void *)hdr + headlen -
			     rxb_addr(preskb->rxb) + rxb_offset(preskb->rxb);

		skb_add_rx_frag(skb, 0, rxb_steal_page(preskb->rxb), offset,
				fraglen, preskb->rxb->truesize);
	}

	memcpy(skb->cb, &preskb->skb_data, sizeof(preskb->skb_data));
}

static void iwl_fmac_rx_frame_eth(struct iwl_fmac *fmac, void *payload,
				  struct rx_data *rx,
				  struct rx_preskb_data *preskb)
{
	struct ethhdr *hdr = payload;
	struct sk_buff *skb;

	if (!iwl_fmac_accept_eth_frame(fmac, hdr, rx))
		return;

	skb = alloc_skb(128, GFP_ATOMIC);
	if (!skb) {
		IWL_ERR(fmac, "alloc_skb failed\n");
		return;
	}
	memset(skb->cb, 0, sizeof(skb->cb));

	iwl_fmac_create_eth_skb(fmac, preskb, skb, hdr);

	if (!iwl_fmac_rx_control_port_check(rx, skb))
		return;

	/* forward to internal stations if needed */
	if (!iwl_fmac_forward_frames(fmac, rx, skb))
		return;

	skb->protocol = eth_type_trans(skb, rx->vif->wdev.netdev);
	if (rx->napi)
		napi_gro_receive(rx->napi, skb);
	else
		netif_receive_skb(skb);
}

static void iwl_fmac_rx_frame(struct iwl_fmac *fmac, void *payload,
			      struct rx_data *rx, struct rx_preskb_data *preskb)
{
	struct ieee80211_hdr *hdr = payload;
	struct sk_buff *skb;
	u8 mac_flags2 = preskb->desc->mac_flags2;

	if (!iwl_fmac_accept_frame(fmac, hdr, rx))
		return;

	if (iwl_fmac_is_dup(fmac, hdr, rx, preskb))
		return;

	/*
	 * Our hardware de-aggregates AMSDUs but copies the mac header
	 * as it to the de-aggregated MPDUs. We need to turn off the
	 * AMSDU bit in the QoS control ourselves.
	 */
	if ((mac_flags2 & IWL_RX_MPDU_MFLG2_AMSDU) &&
	    !WARN_ON(!ieee80211_is_data_qos(hdr->frame_control))) {
		int i;
		u8 *qc = ieee80211_get_qos_ctl(hdr);
		u8 mac_addr[ETH_ALEN];

		*qc &= ~IEEE80211_QOS_CTL_A_MSDU_PRESENT;

		for (i = 0; i < ETH_ALEN; i++)
			mac_addr[i] = hdr->addr3[ETH_ALEN - i - 1];
		ether_addr_copy(hdr->addr3, mac_addr);

		if (ieee80211_has_a4(hdr->frame_control)) {
			for (i = 0; i < ETH_ALEN; i++)
				mac_addr[i] = hdr->addr4[ETH_ALEN - i - 1];
			ether_addr_copy(hdr->addr4, mac_addr);
		}
	}

	if (!ieee80211_has_protected(hdr->frame_control) ||
	    (le16_to_cpu(preskb->desc->status) & IWL_RX_MPDU_STATUS_SEC_MASK) ==
	    IWL_RX_MPDU_STATUS_SEC_NONE) {
		if (iwl_fmac_rx_drop_unencrypted(fmac, hdr, rx))
			return;
	} else if (!iwl_fmac_accept_rx_crypto(fmac, rx, preskb)) {
		return;
	}

	skb = alloc_skb(128, GFP_ATOMIC);
	if (!skb) {
		IWL_ERR(fmac, "alloc_skb failed\n");
		return;
	}
	memset(skb->cb, 0, sizeof(skb->cb));

	iwl_fmac_create_skb(fmac, preskb, skb, hdr,
			    ieee80211_hdrlen(hdr->frame_control));

	if (!iwl_fmac_reorder(fmac, rx, preskb, skb))
		iwl_fmac_prepare_and_deliver_skb(fmac, rx, skb,
						 preskb->mmic_failure);
}

static inline void iwl_fmac_update_rx_stats(struct net_device *dev, u32 len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(netdev_tstats(dev));

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_packets++;
	tstats->rx_bytes += len;
	u64_stats_update_end(&tstats->syncp);
}

static void iwl_fmac_update_sta_rx_stats(struct iwl_fmac *fmac,
					 struct iwl_fmac_sta *sta,
					 struct rx_preskb_data *preskb)
{
	struct iwl_fmac_rx_stats *stats = this_cpu_ptr(sta->info.pcpu_rx_stats);
	__le32 rate_n_flags = (fmac->trans->cfg->device_family >=
			       IWL_DEVICE_FAMILY_22560) ?
		preskb->desc->v3.rate_n_flags : preskb->desc->v1.rate_n_flags;

	stats->last_rx = jiffies;
	stats->last_rate = le32_to_cpu(rate_n_flags);
	stats->signal = iwl_fmac_get_signal_mbm(fmac, preskb->desc);
	stats->packets++;
}

enum {
	IWL_RATE_6M_IEEE  = 12,
	IWL_RATE_9M_IEEE  = 18,
	IWL_RATE_12M_IEEE = 24,
	IWL_RATE_18M_IEEE = 36,
	IWL_RATE_24M_IEEE = 48,
	IWL_RATE_36M_IEEE = 72,
	IWL_RATE_48M_IEEE = 96,
	IWL_RATE_54M_IEEE = 108,
	IWL_RATE_60M_IEEE = 120,
	IWL_RATE_1M_IEEE  = 2,
	IWL_RATE_2M_IEEE  = 4,
	IWL_RATE_5M_IEEE  = 11,
	IWL_RATE_11M_IEEE = 22,
};

static int iwl_fmac_fw_legacy_rate_to_ieee_rate(int rate)
{
	switch (rate) {
	/* OFDM */
	case 0xD:
		return IWL_RATE_6M_IEEE;
	case 0xF:
		return IWL_RATE_9M_IEEE;
	case 0x5:
		return IWL_RATE_12M_IEEE;
	case 0x7:
		return IWL_RATE_18M_IEEE;
	case 0x9:
		return IWL_RATE_24M_IEEE;
	case 0xB:
		return IWL_RATE_36M_IEEE;
	case 0x1:
		return IWL_RATE_48M_IEEE;
	case 0x3:
		return IWL_RATE_54M_IEEE;
	/* CCK */
	case 10:
		return IWL_RATE_1M_IEEE;
	case 20:
		return IWL_RATE_2M_IEEE;
	case 55:
		return IWL_RATE_5M_IEEE;
	case 110:
		return IWL_RATE_11M_IEEE;
	default:
		return -EINVAL;
	}
}

/* Caution: rt_hdr buffer is NOT set to zero (all bytes need to be assigned) */
static int iwl_fmac_rx_fill_radiotap(struct iwl_fmac *fmac,
				     struct ieee80211_radiotap_header *rt_hdr,
				     struct rx_preskb_data *preskb)
{
	__le32 *it_present = &rt_hdr->it_present;
	u32 it_present_val, rate_n_flags, gp2_on_air_rise;
	u8 channel, band, *pos;
	u16 phy_info, rx_status, freq, channel_flags;
	u64 tsf_on_air_rise;
	s8 signal[2]; /* antenna A and B */
	bool legacy;
	int chain, rt_len, legacy_rate;
	unsigned long chains;
	bool rx_ext =
		fmac->trans->cfg->device_family >= IWL_DEVICE_FAMILY_22560;

	rt_hdr->it_version = 0;
	rt_hdr->it_pad = 0;

	phy_info = le16_to_cpu(preskb->desc->phy_info);
	rx_status = le16_to_cpu(preskb->desc->status);
	if (!rx_ext) {
		rate_n_flags = le32_to_cpu(preskb->desc->v1.rate_n_flags);
		tsf_on_air_rise = le64_to_cpu(preskb->desc->v1.tsf_on_air_rise);
		channel = preskb->desc->v1.channel;
		signal[0] = preskb->desc->v1.energy_a
				? -preskb->desc->v1.energy_a : S8_MIN;
		signal[1] = preskb->desc->v1.energy_b
				? -preskb->desc->v1.energy_b : S8_MIN;
		gp2_on_air_rise = le32_to_cpu(preskb->desc->v1.gp2_on_air_rise);
	} else {
		rate_n_flags = le32_to_cpu(preskb->desc->v3.rate_n_flags);
		tsf_on_air_rise = le64_to_cpu(preskb->desc->v3.tsf_on_air_rise);
		channel = preskb->desc->v3.channel;
		signal[0] = preskb->desc->v3.energy_a
				? -preskb->desc->v3.energy_a : S8_MIN;
		signal[1] = preskb->desc->v3.energy_b
				? -preskb->desc->v3.energy_b : S8_MIN;
		gp2_on_air_rise = le32_to_cpu(preskb->desc->v3.gp2_on_air_rise);
	}

	chains = (rate_n_flags & RATE_MCS_ANT_AB_MSK) >> RATE_MCS_ANT_POS;
	legacy = !(rate_n_flags & (RATE_MCS_HT_MSK |
				   RATE_MCS_VHT_MSK |
				   RATE_MCS_HE_MSK));
	band = channel > 14 ? NL80211_BAND_5GHZ : NL80211_BAND_2GHZ;
	freq = ieee80211_channel_to_frequency(channel, band);

	it_present_val = BIT(IEEE80211_RADIOTAP_FLAGS) |
			 BIT(IEEE80211_RADIOTAP_CHANNEL) |
			 BIT(IEEE80211_RADIOTAP_RX_FLAGS) |
			 BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |
			 BIT(IEEE80211_RADIOTAP_TIMESTAMP);

	for_each_set_bit(chain, &chains, 2) {
		it_present_val |=
			BIT(IEEE80211_RADIOTAP_EXT) |
			BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE);
		put_unaligned_le32(it_present_val, it_present);
		it_present++;
		it_present_val = BIT(IEEE80211_RADIOTAP_ANTENNA) |
				 BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
	}
	put_unaligned_le32(it_present_val, it_present);
	pos = (u8 *)(it_present + 1);

	/* MAC timestamp */
	if (!(phy_info & IWL_RX_MPDU_PHY_TSF_OVERLOAD)) {
		/* 2 byte alignment */
		while ((pos - (u8 *)rt_hdr) & 7)
			*pos++ = 0;
		/*
		 * TODO: calculate real timestamp based also on mpdu length
		 * and rate
		 */
		put_unaligned_le64(tsf_on_air_rise, pos);
		rt_hdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_TSFT);
		pos += 8;
	}

	/* Flags */
	*pos = IEEE80211_RADIOTAP_F_FCS;
	if (!(rx_status & IWL_RX_MPDU_STATUS_CRC_OK) ||
	    !(rx_status & IWL_RX_MPDU_STATUS_OVERRUN_OK))
		*pos |= IEEE80211_RADIOTAP_F_BADFCS;
	if (rate_n_flags & RATE_MCS_CCK_MSK &&
	    phy_info & IWL_RX_MPDU_PHY_SHORT_PREAMBLE)
		*pos |= IEEE80211_RADIOTAP_F_SHORTPRE;
	pos++;

	/* Data Rate */
	*pos = 0;
	if (legacy) {
		rt_hdr->it_present |=
				cpu_to_le32(1 << IEEE80211_RADIOTAP_RATE);
		legacy_rate =
			iwl_fmac_fw_legacy_rate_to_ieee_rate(
					rate_n_flags & RATE_LEGACY_RATE_MSK);
		if (!WARN_ON_ONCE(legacy_rate < 0))
			*pos = legacy_rate;
	}
	pos++;

	/* Channel frequency */
	put_unaligned_le16(freq, pos);
	pos += 2;

	/* Channel flags */
	if (band == NL80211_BAND_5GHZ) {
		channel_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_5GHZ;
	} else if (!legacy) {
		channel_flags = IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	} else if (legacy_rate != IWL_RATE_1M_IEEE &&
		   legacy_rate != IWL_RATE_2M_IEEE &&
		   legacy_rate != IWL_RATE_5M_IEEE &&
		   legacy_rate != IWL_RATE_11M_IEEE) {
		/* note: 'legacy' is true => legacy_rate was set before */
		channel_flags = IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ;
	} else {
		channel_flags = IEEE80211_CHAN_CCK | IEEE80211_CHAN_2GHZ;
	}
	put_unaligned_le16(channel_flags, pos);
	pos += 2;

	/* SSI Signal */
	*pos++ = max(signal[0], signal[1]);

	/* 2 byte alignment */
	if ((pos - (u8 *)rt_hdr) & 1)
		*pos++ = 0;

	/* RX flags */
	put_unaligned_le16(0, pos);
	pos += 2;

	/* HT information */
	if (rate_n_flags & RATE_MCS_HT_MSK) {
		u8 stbc =
			(rate_n_flags & RATE_MCS_STBC_MSK) >> RATE_MCS_STBC_POS;

		rt_hdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_MCS);

		*pos++ = 0x3f; /* all bits from ieee80211_radiotap_mcs_have */

		*pos = stbc << IEEE80211_RADIOTAP_MCS_STBC_SHIFT;
		if (!(rate_n_flags & RATE_MCS_CCK_MSK) &&
		    (rate_n_flags & RATE_MCS_SGI_MSK))
			*pos |= IEEE80211_RADIOTAP_MCS_SGI;
		if ((rate_n_flags & RATE_MCS_CHAN_WIDTH_MSK) ==
			RATE_MCS_CHAN_WIDTH_40)
			*pos |= IEEE80211_RADIOTAP_MCS_BW_40;
		if (rate_n_flags & RATE_HT_MCS_GF_MSK)
			*pos |= IEEE80211_RADIOTAP_MCS_FMT_GF;
		if (rate_n_flags & RATE_MCS_LDPC_MSK)
			*pos |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
		pos++;

		*pos++ = rate_n_flags & RATE_HT_MCS_INDEX_MSK;
	}

	/* A-MPDU status */
	if (phy_info & IWL_RX_MPDU_PHY_AMPDU) {
		bool toggle_bit = phy_info & IWL_RX_MPDU_PHY_AMPDU_TOGGLE;
		u16 flags = 0;
		static u32 ampdu_ref;
		static bool ampdu_toggle;

		/* 4 byte alignment */
		while ((pos - (u8 *)rt_hdr) & 3)
			*pos++ = 0;

		rt_hdr->it_present |=
			cpu_to_le32(1 << IEEE80211_RADIOTAP_AMPDU_STATUS);

		put_unaligned_le32(ampdu_ref, pos);
		pos += 4;

		if (toggle_bit != ampdu_toggle) {
			ampdu_toggle = toggle_bit;
			ampdu_ref++;
		}

		/* TODO: HE EOF flags */
		put_unaligned_le16(flags, pos);
		pos += 2;

		put_unaligned_le16(0, pos);
		pos += 2;
	}

	/* VHT information */
	if (rate_n_flags & RATE_MCS_VHT_MSK) {
		u32 mcs = (rate_n_flags & RATE_HT_MCS_INDEX_MSK);
		u32 nss = ((rate_n_flags & RATE_VHT_MCS_NSS_MSK) >>
						RATE_VHT_MCS_NSS_POS) + 1;
		u16 known = IEEE80211_RADIOTAP_VHT_KNOWN_GI |
			    IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH |
			    IEEE80211_RADIOTAP_VHT_KNOWN_STBC |
			    IEEE80211_RADIOTAP_VHT_KNOWN_BEAMFORMED;

		rt_hdr->it_present |= cpu_to_le32(1 << IEEE80211_RADIOTAP_VHT);
		put_unaligned_le16(known, pos);
		pos += 2;

		*pos = 0;
		if (!(rate_n_flags & RATE_MCS_CCK_MSK) &&
		    (rate_n_flags & RATE_MCS_SGI_MSK))
			*pos |= IEEE80211_RADIOTAP_MCS_SGI;
		if (rate_n_flags & RATE_MCS_STBC_MSK)
			*pos |= IEEE80211_RADIOTAP_VHT_FLAG_STBC;
		if (rate_n_flags & RATE_MCS_BF_MSK)
			*pos |= IEEE80211_RADIOTAP_VHT_FLAG_BEAMFORMED;
		pos++;

		switch (rate_n_flags & RATE_MCS_CHAN_WIDTH_MSK) {
		case RATE_MCS_CHAN_WIDTH_40:
			*pos++ = 1;
			break;
		case RATE_MCS_CHAN_WIDTH_80:
			*pos++ = 4;
			break;
		case RATE_MCS_CHAN_WIDTH_160:
			*pos++ = 11;
			break;
		default:
			*pos++ = 0;
		}

		/* MCS index and NSS */
		put_unaligned_le32((mcs << 4) | nss, pos);
		pos += 4;

		*pos = 0;
		if (rate_n_flags & RATE_MCS_LDPC_MSK)
			*pos |= IEEE80211_RADIOTAP_CODING_LDPC_USER0;
		pos++;

		/* group ID */
		*pos++ = 0;

		/* partial aid */
		put_unaligned_le16(0, pos);
		pos += 2;
	}

	/* 8 byte alignment */
	while ((pos - (u8 *)rt_hdr) & 7)
		*pos++ = 0;

	/* timestamp information */
	put_unaligned_le64(gp2_on_air_rise, pos);
	pos += 8;

	put_unaligned_le16(22, pos); /* accuracy */
	pos += 2;

	*pos++ = IEEE80211_RADIOTAP_TIMESTAMP_UNIT_US |
		 IEEE80211_RADIOTAP_TIMESTAMP_SPOS_PLCP_SIG_ACQ;

	*pos++ = IEEE80211_RADIOTAP_TIMESTAMP_FLAG_32BIT |
		 IEEE80211_RADIOTAP_TIMESTAMP_FLAG_ACCURACY;

	/* TODO: HE */
	/* TODO: HE MU */

	/* SSI Signal per chain */
	for_each_set_bit(chain, &chains, 2) {
		*pos++ = signal[chain];
		*pos++ = chain;
	}

	rt_len = pos - (u8 *)rt_hdr;
	rt_hdr->it_len = cpu_to_le16(rt_len);

	return rt_len;
}

static void iwl_fmac_rx_monitor(struct iwl_fmac *fmac,
				struct rx_preskb_data *preskb,
				struct ieee80211_hdr *hdr)
{
#define MAX_RADIOTAP_LEN 128
	u32 rt_len;
	u8 mac_flags2 = preskb->desc->mac_flags2;
	u32 mpdu_len = preskb->len;
	u32 hdr_len = ieee80211_hdrlen(hdr->frame_control);
	u32 pad_len = 0;
	struct sk_buff *skb;

	if (mac_flags2 & IWL_RX_MPDU_MFLG2_PAD)
		pad_len = 2;
	mpdu_len -= pad_len;

	skb = alloc_skb(MAX_RADIOTAP_LEN + mpdu_len, GFP_ATOMIC);
	if (!skb) {
		IWL_ERR(fmac, "alloc_skb failed\n");
		return;
	}
	memset(skb->cb, 0, sizeof(skb->cb));

	rt_len = iwl_fmac_rx_fill_radiotap(fmac, (void *)skb->data, preskb);

	if (WARN_ON(rt_len > MAX_RADIOTAP_LEN)) {
		kfree_skb(skb);
		return;
	}

	skb_put(skb, rt_len);
	skb_put_data(skb, hdr, hdr_len);
	skb_put_data(skb, (u8 *)hdr + hdr_len + pad_len, mpdu_len - hdr_len);

	skb_reset_mac_header(skb);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_OTHERHOST;

	skb->dev = rcu_dereference(fmac->monitor_vif)->wdev.netdev;
	netif_receive_skb(skb);
}

static void iwl_fmac_rx_send_userspace(struct iwl_fmac *fmac,
				       struct iwl_fmac_vif *vif,
				       struct ieee80211_hdr *hdr,
				       struct iwl_rx_mpdu_desc *desc)
{
	bool rx_ext =
		fmac->trans->cfg->device_family >= IWL_DEVICE_FAMILY_22560;
	int len = le16_to_cpu(desc->mpdu_len);
	u8 channel = (rx_ext) ? desc->v3.channel : desc->v1.channel;
	enum nl80211_band band = channel > 14 ? NL80211_BAND_5GHZ :
						NL80211_BAND_2GHZ;
	int freq = ieee80211_channel_to_frequency(channel, band);
	int sig = iwl_fmac_get_signal_mbm(fmac, desc);

	/* TODO: check if we need to return the action frame */
	cfg80211_rx_mgmt(&vif->wdev, freq, sig, (void *)hdr, len, 0);
}

static bool iwl_fmac_rx_netdev_frame(struct iwl_fmac *fmac,
				     struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct ieee80211_hdr *hdr;
	bool rx_ext =
		fmac->trans->cfg->device_family >= IWL_DEVICE_FAMILY_22560;
	struct iwl_rx_mpdu_desc *desc = (void *)pkt->data;

	if (rx_ext)
		hdr = (void *)(pkt->data + sizeof(*desc));
	else
		hdr = (void *)(pkt->data + IWL_RX_DESC_SIZE_V1);

	if (ieee80211_is_frag(hdr)) {
		IWL_ERR(fmac, "No support for fragmentation (yet)\n");
		return false;
	}

	if (ieee80211_is_beacon(hdr->frame_control) ||
	    ieee80211_is_probe_resp(hdr->frame_control)) {
		u8 channel = (rx_ext) ? desc->v3.channel : desc->v1.channel;
		enum nl80211_band band = channel > 14 ?
						NL80211_BAND_5GHZ :
						NL80211_BAND_2GHZ;
		int freq = ieee80211_channel_to_frequency(channel,
							  band);
		int len = le16_to_cpu(desc->mpdu_len);
		struct cfg80211_inform_bss data = {
			.chan = ieee80211_get_channel(wiphy_from_fmac(fmac),
						      freq),
			.scan_width = NL80211_BSS_CHAN_WIDTH_20,
			.signal = iwl_fmac_get_signal_mbm(fmac, desc),
		};
		struct cfg80211_bss *bss;

		if (WARN_ON(!data.chan))
			return false;

		if (data.chan->flags & IEEE80211_CHAN_DISABLED)
			return false;

		bss = cfg80211_inform_bss_frame_data(wiphy_from_fmac(fmac),
						     &data, (void *)hdr,
						     len, GFP_ATOMIC);
		cfg80211_put_bss(wiphy_from_fmac(fmac), bss);
		return false;
	}

	/* Drop NDPs */
	if (ieee80211_is_nullfunc(hdr->frame_control) ||
	    ieee80211_is_qos_nullfunc(hdr->frame_control)) {
		IWL_ERR(fmac, "Got a NullFunc packet... Bug in firmware\n");
		return false;
	}

	if (ieee80211_is_mgmt(hdr->frame_control)) {
		struct iwl_fmac_vif *host_based_ap_vif;

		rcu_read_lock();
		host_based_ap_vif = rcu_dereference(fmac->host_based_ap_vif);

		if (host_based_ap_vif) {
			iwl_fmac_rx_send_userspace(fmac, host_based_ap_vif,
						   hdr, desc);
		} else {
			/*
			 * We don't expect any mgmt frame besides the ones
			 * we accecpted above
			 */
			IWL_ERR(fmac,
				"Got a mgmt packet... FC: 0x%x - Bug in firmware\n",
				le16_to_cpu(hdr->frame_control));
		}
		rcu_read_unlock();

		return false;
	}
	return true;
}

void iwl_fmac_rx_mpdu(struct iwl_fmac *fmac, struct napi_struct *napi,
		      struct iwl_rx_cmd_buffer *rxb, int queue)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct rx_data rx = {
		.queue = queue,
		.napi = napi,
	};
	struct rx_preskb_data preskb = {
		.rxb = rxb,
	};
	struct ieee80211_hdr *hdr;
	__le16 status;
	u8 sta_id_flags;
	bool eth;


	preskb.desc = (void *)pkt->data;
	preskb.len = le16_to_cpu(preskb.desc->mpdu_len);
	eth = le16_to_cpu(preskb.desc->phy_info) & IWL_RX_MPDU_PHY_8023;

	/*
	 * For 802.3 mode we have padding of 2 bytes, since L3 payload must be
	 * aligned to 8-byte boundary.
	 */
	if (eth)
		hdr = (void *)(pkt->data + sizeof(*preskb.desc) + 2);
	else if (fmac->trans->cfg->device_family >= IWL_DEVICE_FAMILY_22560)
		hdr = (void *)(pkt->data + sizeof(*preskb.desc));
	else
		hdr = (void *)(pkt->data + IWL_RX_DESC_SIZE_V1);

	if (WARN_ON(preskb.len < 2))
		return;

	rcu_read_lock();
	if (rcu_access_pointer(fmac->monitor_vif)) {
		iwl_fmac_rx_monitor(fmac, &preskb, hdr);
		/* are there other vif's to handle? */
		if (atomic_read(&fmac->open_count) <= 1) {
			rcu_read_unlock();
			return;
		}
	}
	rcu_read_unlock();

	/* the firmware shouldn't be passing any control frame */
	if (ieee80211_is_ctl(hdr->frame_control)) {
		IWL_ERR(fmac,
			"Got a ctrl packet... FC: 0x%x - Bug in firmware\n",
			le16_to_cpu(hdr->frame_control));
		return;
	}

	if (WARN(preskb.len < 24, "Frame is too short: %d - FC: 0x%02x",
		 preskb.len, le16_to_cpu(hdr->frame_control)))
		return;

	if (!eth && !iwl_fmac_rx_netdev_frame(fmac, rxb))
		return;

	rcu_read_lock();

	status = preskb.desc->status;
	sta_id_flags = preskb.desc->sta_id_flags;

	if (status & cpu_to_le16(IWL_RX_MPDU_STATUS_SRC_STA_FOUND)) {
		u8 id = sta_id_flags & IWL_RX_MPDU_SIF_STA_ID_MASK;

		if (WARN_ON_ONCE(id >= ARRAY_SIZE(fmac->stas)))
			goto out;

		rx.sta = rcu_dereference(fmac->stas[id]);

		/* this station may be unknown to us (added by UMAC) */
		if (!rx.sta || WARN_ON(rx.sta->sta_id != id))
			rx.sta = NULL;
	}

	if (!rx.sta) {
		struct ieee80211_hdr *_hdr = hdr;

		rx.sta = iwl_get_sta(fmac, _hdr->addr2);
	}

	if (rx.sta && !is_multicast_ether_addr(rx.sta->addr)) {
		rx.vif = rx.sta->vif;
		if (eth)
			iwl_fmac_rx_frame_eth(fmac, hdr, &rx, &preskb);
		else
			iwl_fmac_rx_frame(fmac, hdr, &rx, &preskb);
		iwl_fmac_update_rx_stats(rx.vif->wdev.netdev, preskb.len);
		iwl_fmac_update_sta_rx_stats(fmac, rx.sta, &preskb);
		/*
		 * management frames could possibly be interesting for
		 * other interfaces, but we shouldn't really get any of
		 * those in the host driver anyway.
		 */
	} else {
		WARN(rx.sta, "Got Rx on bcast station\n");
		/* TODO: don't drop 802.1X frames (check for control port) */
	}

out:
	rcu_read_unlock();
}

void iwl_fmac_rx_frame_release(struct iwl_fmac *fmac, struct napi_struct *napi,
			       struct iwl_rx_packet *pkt, int queue)
{
	struct iwl_frame_release *release = (void *)pkt->data;
	struct iwl_fmac_sta *sta;
	struct iwl_fmac_reorder_buffer *buffer;
	int baid = release->baid;
	struct rx_data rx = {
		.queue = queue,
	};

	IWL_DEBUG_HT(fmac, "Frame release notification for BAID %u, NSSN %d\n",
		     baid, le16_to_cpu(release->nssn));

	if (WARN_ON_ONCE(baid >= IWL_MAX_BAID))
		return;

	buffer = &fmac->reorder_bufs[baid][queue];
	if (buffer->sta_id >= IWL_FMAC_MAX_STA)
		return;

	rcu_read_lock();
	sta = rcu_dereference(fmac->stas[buffer->sta_id]);
	if (WARN_ON_ONCE(!sta))
		goto out;

	rx.sta = sta;
	rx.vif = sta->vif;

	spin_lock_bh(&buffer->lock);
	iwl_fmac_release_frames(fmac, buffer, &rx, le16_to_cpu(release->nssn));
	spin_unlock_bh(&buffer->lock);

out:
	rcu_read_unlock();
}

void iwl_fmac_rx_delba_ntfy(struct iwl_fmac *fmac, struct iwl_rx_packet *pkt,
			    int queue)
{
	struct iwl_rx_sync_delba *delba = (void *)pkt->data;
	struct iwl_fmac_sta *sta;
	struct iwl_fmac_reorder_buffer *buffer;

	if (WARN_ON_ONCE(delba->sta_id >= IWL_FMAC_MAX_STA))
		return;
	if (WARN_ON_ONCE(delba->ba_id >= IWL_MAX_BAID))
		return;

	rcu_read_lock();
	sta = rcu_dereference(fmac->stas[delba->sta_id]);
	if (!sta)
		goto out;

	buffer = &fmac->reorder_bufs[delba->ba_id][queue];
	iwl_fmac_destroy_reorder_buffer(fmac, sta, buffer);

 out:
	rcu_read_unlock();
}

/******************************************************************************
 *
 * This file is provided under GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright 2002-2005, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014  Intel Mobile Communications GmbH
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
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "fmac.h"

#include "fw-api.h"
#include "fw/api/binding.h"

#define MICHAEL_MIC_LEN 8

#define OPT_HDR(type, skb, off) \
	(type *)(skb_network_header(skb) + (off))

static int iwl_fmac_csum_prepare(struct iwl_fmac *fmac, struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_INET)
	u8 protocol = 0;

	/* Do not compute checksum if already computed by stack */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return -1;

	/* We do not expect to be requested to csum stuff we do not support */
	if (WARN_ONCE(!fw_has_capa(&fmac->fw->ucode_capa,
				   IWL_UCODE_TLV_CAPA_CSUM_SUPPORT) ||
		      (skb->protocol != htons(ETH_P_IP) &&
		       skb->protocol != htons(ETH_P_IPV6)),
		      "No support for requested checksum\n"))
		goto no_offload;

	if (skb->protocol == htons(ETH_P_IP)) {
		protocol = ip_hdr(skb)->protocol;
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		struct ipv6hdr *ipv6h =
			(struct ipv6hdr *)skb_network_header(skb);
		unsigned int off = sizeof(*ipv6h);

		protocol = ipv6h->nexthdr;
		while (protocol != NEXTHDR_NONE && ipv6_ext_hdr(protocol)) {
			struct ipv6_opt_hdr *hp;

			/* only supported extension headers */
			if (protocol != NEXTHDR_ROUTING &&
			    protocol != NEXTHDR_HOP &&
			    protocol != NEXTHDR_DEST)
				goto no_offload;

			hp = OPT_HDR(struct ipv6_opt_hdr, skb, off);
			protocol = hp->nexthdr;
			off += ipv6_optlen(hp);
		}
		/* if we get here - protocol now should be TCP/UDP */
#endif
	}

	if (WARN_ON_ONCE(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP))
		goto no_offload;

	if (skb->protocol == htons(ETH_P_IP))
		ip_hdr(skb)->check = 0;

	/* reset UDP/TCP header csum */
	if (protocol == IPPROTO_TCP)
		tcp_hdr(skb)->check = 0;
	else
		udp_hdr(skb)->check = 0;

	return 0;

no_offload:
	skb_checksum_help(skb);
#endif
	return -1;
}

static inline void iwl_fmac_update_tx_stats(struct net_device *dev, u32 len)
{
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(netdev_tstats(dev));

	u64_stats_update_begin(&tstats->syncp);
	tstats->tx_packets++;
	tstats->tx_bytes += len;
	u64_stats_update_end(&tstats->syncp);
}

static struct sk_buff *iwl_fmac_build_80211_hdr(struct sk_buff *skb,
						struct net_device *dev,
						struct iwl_fmac_tx_data *tx)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac *fmac = vif->fmac;
	u16 hdrlen;
	struct ieee80211_hdr hdr = {};
	const u8 *encaps_data;
	int ret;
	__le16 fc = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA);
	struct iwl_fmac_skb_info *info = (void *)skb->cb;

	/* convert Ethernet header to 802.11 header */

	switch (vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
		fc |= cpu_to_le16(IEEE80211_FCTL_TODS);

		/* BSSID SA DA */
		ether_addr_copy(hdr.addr1, tx->sta->addr);
		ether_addr_copy(hdr.addr2, skb->data + ETH_ALEN);
		if (info->amsdu)
			ether_addr_copy(hdr.addr3, tx->sta->addr);
		else
			ether_addr_copy(hdr.addr3, skb->data);
		hdrlen = 24;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		fc |= cpu_to_le16(IEEE80211_FCTL_FROMDS);

		/* DA BSSID SA */
		ether_addr_copy(hdr.addr1, skb->data);
		ether_addr_copy(hdr.addr2, dev->dev_addr);
		if (info->amsdu)
			ether_addr_copy(hdr.addr3, dev->dev_addr);
		else
			ether_addr_copy(hdr.addr3, skb->data + ETH_ALEN);
		hdrlen = 24;
		break;
	default:
		IWL_WARN(vif->fmac, "Invalid iftype\n");
		ret = -EINVAL;
		goto free;
	}

	if (!info->amsdu) {
		u16 eth_type = (skb->data[12] << 8) | skb->data[13];
		int encaps_len, skip_header_bytes;

		/* remove the eth hdr */
		skip_header_bytes = ETH_HLEN;
		if (eth_type == ETH_P_AARP || eth_type == ETH_P_IPX) {
			encaps_data = bridge_tunnel_header;
			encaps_len = sizeof(bridge_tunnel_header);
			skip_header_bytes -= 2;
		} else if (eth_type >= ETH_P_802_3_MIN) {
			encaps_data = rfc1042_header;
			encaps_len = sizeof(rfc1042_header);
			skip_header_bytes -= 2;
		} else {
			encaps_data = NULL;
			encaps_len = 0;
		}

		skb_pull(skb, skip_header_bytes);

		if (encaps_data)
			memcpy(skb_push(skb, encaps_len), encaps_data,
			       encaps_len);
	}

	if (tx->key) {
		fc |= cpu_to_le16(IEEE80211_FCTL_PROTECTED);

		switch (tx->key->cipher) {
		case IWL_FMAC_CIPHER_WEP40:
		case IWL_FMAC_CIPHER_WEP104:
			/* The HW adds the IV and doesn't even need to allcoate
			 * room for it.
			 */
			break;
		case IWL_FMAC_CIPHER_CCMP:
		case IWL_FMAC_CIPHER_CCMP_256:
		case IWL_FMAC_CIPHER_GCMP:
		case IWL_FMAC_CIPHER_GCMP_256:
			if (iwl_fmac_has_new_tx_api(fmac))
				break;
			skb_push(skb, tx->key->iv_len);
			break;
		case IWL_FMAC_CIPHER_TKIP:
			if (fmac->trans->cfg->gen2) {
				ret = skb_linearize(skb);
				if (ret)
					goto free;
				break;
			}
			/* Fall through */
		default:
			IWL_ERR(vif->fmac, "Cipher %d isn't supported\n",
				tx->key->cipher);
		}
	}
	hdr.frame_control = fc;

	if (tx->sta->qos) {
		u8 *qos_control;
		u8 tid;

		hdr.frame_control |= cpu_to_le16(IEEE80211_STYPE_QOS_DATA);
		hdrlen += 2;

		qos_control = skb_push(skb, 2);
		memcpy(skb_push(skb, hdrlen - 2), &hdr, hdrlen - 2);

		tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;
		/*TODO in case of Access Controlled downgrade tid (look at
		 *ieee80211_downgrade
		 */
		/*TODO multicast and noack_map not dealt */

		if (info->amsdu)
			tid |= IEEE80211_QOS_CTL_A_MSDU_PRESENT;

		*qos_control++ = tid;
		*qos_control = 0;
	} else {
		memcpy(skb_push(skb, hdrlen), &hdr, hdrlen);
	}

	return skb;
free:
	kfree_skb(skb);
	return ERR_PTR(ret);
}

static void iwl_fmac_tx_set_sta(struct sk_buff *skb,
				struct iwl_fmac_tx_data *tx)
{
	struct iwl_fmac_vif *vif = tx->vif;
	const u8 *addr = skb->data;

	switch (vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
		/* TODO: TDLS */
		tx->sta = rcu_dereference(vif->u.mgd.ap_sta);
		if (!tx->sta)
			IWL_ERR(vif->fmac, "AP station not initialized\n");
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		if (is_multicast_ether_addr(addr))
			addr = MCAST_STA_ADDR;

		tx->sta = iwl_get_sta(vif->fmac, addr);
		if (!tx->sta)
			IWL_ERR(vif->fmac, "no destination STA for %pM\n",
				addr);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

static void iwl_fmac_set_ccm_gcm_pn(struct sk_buff *skb,
				    struct iwl_fmac_tx_data *tx,
				    int hdrlen)
{
	u8 *crypto_hdr = skb->data + hdrlen;
	u64 pn;

	pn = atomic64_inc_return(&tx->key->tx_pn);
	crypto_hdr[0] = pn;
	crypto_hdr[2] = 0;
	crypto_hdr[3] = 0x20 | (tx->key->keyidx << 6);
	crypto_hdr[1] = pn >> 8;
	crypto_hdr[4] = pn >> 16;
	crypto_hdr[5] = pn >> 24;
	crypto_hdr[6] = pn >> 32;
	crypto_hdr[7] = pn >> 40;
}

static void iwl_fmac_tx_set_pn(struct sk_buff *skb, struct iwl_fmac_tx_data *tx)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	int hdrlen = ieee80211_hdrlen(hdr->frame_control);

	switch (tx->key->cipher) {
	case IWL_FMAC_CIPHER_GCMP:
	case IWL_FMAC_CIPHER_GCMP_256:
	case IWL_FMAC_CIPHER_CCMP:
	case IWL_FMAC_CIPHER_CCMP_256:
		iwl_fmac_set_ccm_gcm_pn(skb, tx, hdrlen);
		break;
	case IWL_FMAC_CIPHER_WEP104:
	case IWL_FMAC_CIPHER_WEP40:
		break;
	case IWL_FMAC_CIPHER_TKIP:
		WARN_ON_ONCE(1);
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

void iwl_fmac_tx_set_key(struct sk_buff *skb, struct iwl_fmac_tx_data *tx)
{
	struct iwl_fmac_sta *sta = tx->sta;

	switch (tx->vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
		if (sta->encryption)
			tx->key = rcu_dereference(sta->ptk[sta->ptk_idx]);
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_P2P_GO:
		if (sta->encryption) {
			if (is_multicast_ether_addr(sta->addr)) {
				tx->key =
					rcu_dereference(sta->gtk[sta->gtk_idx]);
				WARN_ON_ONCE(!tx->key);
			} else {
				tx->key =
					rcu_dereference(sta->ptk[sta->ptk_idx]);
				WARN_ON_ONCE(!tx->key);
			}
		}
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

static void iwl_fmac_tx_add_stream(struct iwl_fmac *fmac,
				   struct iwl_fmac_sta *sta, u8 tid,
				   struct sk_buff *skb)
{
	struct sk_buff_head *deferred_tx_frames;
	u8 ac;

	lockdep_assert_held(&sta->lock);

	sta->deferred_traffic_tid_map |= BIT(tid);
	set_bit(sta->sta_id, fmac->sta_deferred_frames);

	deferred_tx_frames = &sta->tids[tid].deferred_tx_frames;

	skb_queue_tail(deferred_tx_frames, skb);

	ac = tid_to_ac[tid];

	/*
	 * The first deferred frame stops the ac netdev queue, so we
	 * should never get a second deferred frame for the RA/TID.
	 */
	if (!WARN(skb_queue_len(deferred_tx_frames) != 1,
		  "RATID %d/%d has %d deferred frames\n", sta->sta_id, tid,
		  skb_queue_len(deferred_tx_frames))) {
		iwl_fmac_stop_ac_queue(fmac, &sta->vif->wdev, ac);
		schedule_work(&fmac->add_stream_wk);
	}
}

static const u8 iwl_fmac_11ax_tid_to_tx_fifo[] = {
	IWL_GEN2_TRIG_TX_FIFO_BE,
	IWL_GEN2_TRIG_TX_FIFO_BK,
	IWL_GEN2_TRIG_TX_FIFO_BK,
	IWL_GEN2_TRIG_TX_FIFO_BE,
	IWL_GEN2_TRIG_TX_FIFO_VI,
	IWL_GEN2_TRIG_TX_FIFO_VI,
	IWL_GEN2_TRIG_TX_FIFO_VO,
	IWL_GEN2_TRIG_TX_FIFO_VO,
	IWL_GEN2_TRIG_TX_FIFO_VO /* MGMT is mapped to VO */
};

static unsigned int iwl_fmac_max_amsdu_size(struct iwl_fmac *fmac,
					    struct iwl_fmac_sta *sta,
					    unsigned int tid)
{
	unsigned int txf;
	int lmac = IWL_LMAC_24G_INDEX;

	if (fw_has_capa(&fmac->fw->ucode_capa,
			IWL_UCODE_TLV_CAPA_CDB_SUPPORT) &&
	    sta->band == NL80211_BAND_5GHZ)
		lmac = IWL_LMAC_5G_INDEX;

	if (sta->he)
		txf = iwl_fmac_11ax_tid_to_tx_fifo[tid];
	else
		txf = iwl_fmac_tid_to_tx_fifo[tid];

	/*
	 * Don't send an AMSDU that will be longer than the TXF.
	 * Add a security margin of 256 for the TX command + headers.
	 * We also want to have the start of the next packet inside the
	 * fifo to be able to send bursts.
	 */
	return min_t(unsigned int, sta->amsdu_size,
		     fmac->fwrt.smem_cfg.lmac[lmac].txfifo_size[txf] - 256);
}

static void iwl_fmac_xmit_one(struct sk_buff *skb,
			      struct iwl_fmac_tx_data *tx)
{
	struct iwl_fmac_vif *vif = tx->vif;

	iwl_fmac_tx_set_key(skb, tx);

	skb = iwl_fmac_build_80211_hdr(skb, vif->wdev.netdev, tx);
	if (IS_ERR(skb))
		return;

	if (tx->key && !iwl_fmac_has_new_tx_api(vif->fmac))
		iwl_fmac_tx_set_pn(skb, tx);

	iwl_fmac_update_tx_stats(vif->wdev.netdev, skb->len);
	if (iwl_fmac_tx_skb(vif->fmac, skb, tx))
		dev_kfree_skb(skb);
}

static void iwl_fmac_convert_eth_to_amsdu(struct sk_buff *skb)
{
	struct ethhdr *eth = (void *)skb->data;
	struct ethhdr *amsduhdr;

	amsduhdr = skb_push(skb, sizeof(rfc1042_header) + 2);
	memmove(amsduhdr, eth, 2 * ETH_ALEN);
	memcpy(amsduhdr + 1, rfc1042_header, sizeof(rfc1042_header));
	amsduhdr->h_proto = htons(skb->len - sizeof(*amsduhdr));
}

static void iwl_fmac_store_xmit_skb(struct iwl_fmac *fmac,
				    struct iwl_fmac_amsdu_data *store,
				    struct sk_buff *skb)
{
	memset(store, 0, sizeof(*store));
	store->skb = skb;
	store->csum = iwl_fmac_csum_prepare(fmac, skb);
	store->deadline =
		ktime_add_ns(ktime_get(),
			     iwlfmac_mod_params.amsdu_delay * NSEC_PER_MSEC);
}

static struct sk_buff *iwl_fmac_xmit_amsdu(struct iwl_fmac_vif *vif,
					   struct sk_buff *skb,
					   unsigned int tid,
					   struct iwl_fmac_tx_data *tx)
{
	struct iwl_fmac_amsdu_data *store = &tx->sta->amsdu[tid];
	struct sk_buff *prev = store->skb;
	struct iwl_fmac_skb_info *info;
	unsigned int new_len;
	unsigned int add_tbs;

	if (!prev) {
		iwl_fmac_store_xmit_skb(vif->fmac, store, skb);
		return NULL;
	}

	/* add a frame to the pending (prev) if possible */

	info = (void *)prev->cb;

	new_len = prev->len + skb->len + 8 /* SNAP */ + 3 /* max pad */;
	/* header + # of frags in this one */
	add_tbs = 1 + skb_shinfo(skb)->nr_frags;

	/* if it gets too long or too many pieces: flush */
	if (new_len > iwl_fmac_max_amsdu_size(vif->fmac, tx->sta, tid) ||
	    store->amsdu_tbs + add_tbs > vif->fmac->trans->max_skb_frags) {
		iwl_fmac_store_xmit_skb(vif->fmac, store, skb);
		return prev;
	}

	/*
	 * If the stored frame was only stored, not made into an A-MSDU
	 * yet, then do that now. We don't do it while storing so that
	 * we can still send it as a single frame if we have nothing
	 * else to send later.
	 */
	if (!store->amsdu_subframes) {
		store->amsdu_subframes = 1;
		/* the header is already accounted for by the PCIe code */
		store->amsdu_tbs = skb_shinfo(prev)->nr_frags;
		info->amsdu = true;

		iwl_fmac_convert_eth_to_amsdu(prev);
		skb_shinfo(prev)->frag_list = skb;
	} else {
		struct sk_buff *tail;

		tail = skb_shinfo(prev)->frag_list;
		while (tail->next)
			tail = tail->next;
		tail->next = skb;
	}

	iwl_fmac_convert_eth_to_amsdu(skb);

	/*
	 * Pad out the previous subframe to a multiple of 4 by adding the
	 * padding to the next one, that's being added. Note that prev->len
	 * is the length of the full A-MSDU, but that works since each time
	 * we add a new subframe we pad out the previous one to a multiple
	 * of 4 and thus it no longer matters in the next round.
	 */
	if (prev->len & 3) {
		unsigned int pad = 4 - (prev->len & 3);

		memset(skb_push(skb, pad), 0, pad);
	}

	/* account for the new frag skb */
	prev->len += skb->len;
	prev->data_len += skb->len;
	store->amsdu_subframes++;
	store->amsdu_tbs += add_tbs;

	/*
	 * We currently don't know the station's limit (from extended
	 * capabilities) so just restrict to the lowest possible, i.e. 8.
	 */
	if (store->amsdu_subframes == 8) {
		memset(store, 0, sizeof(*store));
		return prev;
	}

	return NULL;
}

static void iwl_fmac_set_amsdu_timer(struct iwl_fmac_vif *vif)
{
	struct iwl_fmac *fmac = vif->fmac;
	int sta_id, tid;
	bool first = true;
	ktime_t next;

	for (sta_id = 0; sta_id < IWL_FMAC_MAX_STA; sta_id++) {
		struct iwl_fmac_sta *sta = rcu_dereference(fmac->stas[sta_id]);

		if (IS_ERR_OR_NULL(sta))
			continue;

		spin_lock(&sta->amsdu_lock);
		for (tid = 0; tid < IWL_MAX_TID_COUNT; tid++) {
			if (!sta->amsdu[tid].skb)
				continue;
			if (first) {
				next = sta->amsdu[tid].deadline;
				first = false;
			} else if (ktime_before(sta->amsdu[tid].deadline,
						next)) {
				next = sta->amsdu[tid].deadline;
			}
		}
		spin_unlock(&sta->amsdu_lock);
	}

	if (first)
		return;

	tasklet_hrtimer_start(&vif->amsdu_timer, next, HRTIMER_MODE_ABS);
}

enum hrtimer_restart iwl_fmac_amsdu_xmit_timer(struct hrtimer *timer)
{
	struct iwl_fmac_vif *vif = container_of(timer, struct iwl_fmac_vif,
						amsdu_timer.timer);
	struct iwl_fmac *fmac = vif->fmac;
	int sta_id, tid;
	ktime_t cur = ktime_get();

	rcu_read_lock();
	for (sta_id = 0; sta_id < IWL_FMAC_MAX_STA; sta_id++) {
		struct iwl_fmac_sta *sta = rcu_dereference(fmac->stas[sta_id]);

		if (IS_ERR_OR_NULL(sta))
			continue;

		spin_lock(&sta->amsdu_lock);
		for (tid = 0; tid < IWL_MAX_TID_COUNT; tid++) {
			struct iwl_fmac_tx_data tx = {
				.vif = vif,
				.sta = sta,
			};

			if (!sta->amsdu[tid].skb ||
			    ktime_before(cur, sta->amsdu[tid].deadline))
				continue;
			iwl_fmac_xmit_one(sta->amsdu[tid].skb, &tx);
			memset(&sta->amsdu[tid], 0, sizeof(sta->amsdu[tid]));
		}
		spin_unlock(&sta->amsdu_lock);
	}

	iwl_fmac_set_amsdu_timer(vif);
	rcu_read_unlock();

	return HRTIMER_NORESTART;
}

static void iwl_fmac_xmit_queue(struct iwl_fmac_vif *vif,
				struct sk_buff_head *skbs)
{
	struct iwl_fmac_sta *stas[IWL_FMAC_MAX_STA] = {};
	struct sk_buff *skb;
	int sta_id, tid;
	bool can_agg;

	while ((skb = __skb_dequeue(skbs))) {
		struct iwl_fmac_skb_info *info = (void *)skb->cb;
		struct ethhdr *eth = (void *)skb->data;
		struct iwl_fmac_tx_data tx = {
			.vif = vif,
		};
		bool csum;
		struct sk_buff *old;

		memset(info, 0, sizeof(*info));

		iwl_fmac_tx_set_sta(skb, &tx);
		if (!tx.sta) {
			kfree_skb(skb);
			continue;
		}

		if (!tx.sta->authorized &&
		    eth->h_proto != vif->control_port_ethertype) {
			kfree_skb(skb);
			continue;
		}

		sta_id = tx.sta->sta_id;
		tid = skb->priority & IEEE80211_QOS_CTL_TAG1D_MASK;

		can_agg = !skb_is_gso(skb) && tx.sta->amsdu_enabled &&
			ntohs(eth->h_proto) >= ETH_P_802_3_MIN;
		csum = iwl_fmac_csum_prepare(vif->fmac, skb);

		spin_lock(&tx.sta->amsdu_lock);
		old = tx.sta->amsdu[tid].skb;
		if (old && (tx.sta->amsdu[tid].csum != csum || !can_agg))
			memset(&tx.sta->amsdu[tid], 0,
			       sizeof(tx.sta->amsdu[tid]));
		else
			old = NULL;
		spin_unlock(&tx.sta->amsdu_lock);

		if (old)
			iwl_fmac_xmit_one(old, &tx);

		/*
		 * If it's GSO, or an ethertype requiring a different header
		 * than RFC 1042 (which we don't want to handle inside A-MSDU),
		 * or A-MSDU is not (or no longer) enabled, then send both an
		 * old frame (if it exists) and the next one to prevent
		 * reordering.
		 */
		if (!can_agg) {
			iwl_fmac_xmit_one(skb, &tx);
			continue;
		}

		if (!stas[sta_id])
			stas[sta_id] = tx.sta;

		spin_lock(&tx.sta->amsdu_lock);
		skb = iwl_fmac_xmit_amsdu(vif, skb, tid, &tx);
		spin_unlock(&tx.sta->amsdu_lock);

		if (skb)
			iwl_fmac_xmit_one(skb, &tx);
	}

	/*
	 * If we should wait for frames to build A-MSDUs, then only send the
	 * full A-MSDUs and unaggregatable frames above, and leave the rest
	 * to the timer.
	 */
	if (iwlfmac_mod_params.amsdu_delay) {
		rcu_read_lock();
		iwl_fmac_set_amsdu_timer(vif);
		rcu_read_unlock();
		return;
	}

	/* send out remaining ones we couldn't aggregate */
	for (sta_id = 0; sta_id < IWL_FMAC_MAX_STA; sta_id++) {
		struct iwl_fmac_tx_data tx = {
			.vif = vif,
			.sta = stas[sta_id],
		};

		if (!tx.sta)
			continue;

		spin_lock(&stas[sta_id]->amsdu_lock);
		for (tid = 0; tid < IWL_MAX_TID_COUNT; tid++) {
			if (!tx.sta->amsdu[tid].skb)
				continue;

			iwl_fmac_xmit_one(tx.sta->amsdu[tid].skb, &tx);
			memset(&tx.sta->amsdu[tid], 0,
			       sizeof(tx.sta->amsdu[tid]));
		}
		spin_unlock(&stas[sta_id]->amsdu_lock);
	}
}

netdev_tx_t iwl_fmac_dev_start_xmit(struct sk_buff *skb,
				    struct net_device *dev)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	int ac = skb_get_queue_mapping(skb);

	/* TODO: This code needs rework towards AP / TDLS.
	 *	 We need to get the station before we build the header
	 */

	if (iwl_fmac_is_radio_killed(vif->fmac)) {
		IWL_DEBUG_DROP(vif->fmac, "Dropping - RF/CT KILL\n");
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	/* If the skb is shared clone it before you change it */
	if (skb_shared(skb)) {
		struct sk_buff *sk_tmp = skb;

		skb = skb_clone(skb, GFP_ATOMIC);
		kfree_skb(sk_tmp);

		if (!skb)
			return NETDEV_TX_OK;
	}

	rcu_read_lock();

	BUILD_BUG_ON(sizeof(struct iwl_fmac_skb_info) > sizeof(skb->cb));

	__skb_queue_tail(&vif->pending_skbs[ac], skb);

	if (skb_xmit_more(skb))
		goto out;

	iwl_fmac_xmit_queue(vif, &vif->pending_skbs[ac]);
out:
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static void iwl_fmac_reclaim_and_free(struct iwl_fmac *fmac, u8 sta_id, u8 tid,
				      u16 txq_id, u16 ssn, bool ack)
{
	struct sk_buff_head reclaimed_skbs;
	struct iwl_fmac_sta *sta;

	__skb_queue_head_init(&reclaimed_skbs);

	/* we can free until ssn % q.n_bd not inclusive */
	iwl_trans_reclaim(fmac->trans, txq_id, ssn, &reclaimed_skbs);

	rcu_read_lock();
	sta = rcu_dereference(fmac->stas[sta_id]);

	while (!skb_queue_empty(&reclaimed_skbs)) {
		struct sk_buff *skb = __skb_dequeue(&reclaimed_skbs);
		struct iwl_fmac_skb_info *skb_info = (void *)skb->cb;

		if (skb_info->cookie && sta)
			cfg80211_mgmt_tx_status(&sta->vif->wdev,
						skb_info->cookie, skb->data,
						skb->len, ack, GFP_ATOMIC);

		iwl_trans_free_tx_cmd(fmac->trans, skb_info->dev_cmd);

		dev_kfree_skb(skb);
	}


	/*
	 * The station typically shouldn't be NULL, since that would mean we
	 * have TX frames released from a queue it owned after the station
	 * was removed.
	 * This can, however, legitimately happen while we remove the station,
	 * we have to remove it from the array before we flush the queues so
	 * that we stop transmitting to those queues, and then the completions
	 * might only happen after it's removed (while removing queues.)
	 */
	if (!sta)
		goto out;

	/* If this is an aggregation queue, we use the ssn since:
	 * ssn = wifi seq_num % 256.
	 * The seq_ctl is the sequence control of the packet to which
	 * this Tx response relates. But if there is a hole in the
	 * bitmap of the BA we received, this Tx response may allow to
	 * reclaim the hole and all the subsequent packets that were
	 * already acked. In that case, seq_ctl != ssn, and the next
	 * packet to be reclaimed will be ssn and not seq_ctl. In that
	 * case, several packets will be reclaimed even if
	 * frame_count = 1.
	 *
	 * The ssn is the index (% 256) of the latest packet that has
	 * treated (acked / dropped) + 1.
	 */

	/* TODO: when TXQ is shared, next_reclaimed is the one after this one */

	if (sta->qos && tid != IWL_MAX_TID_COUNT)
		sta->tids[tid].next_reclaimed = ssn;

out:
	rcu_read_unlock();
}

static struct agg_tx_status *
iwl_fmac_get_agg_status(struct iwl_fmac *fmac, struct iwl_mvm_tx_resp *tx_resp)
{
	if (iwl_fmac_has_new_tx_api(fmac))
		return &((struct iwl_mvm_tx_resp *)tx_resp)->status;
	else
		return ((struct iwl_mvm_tx_resp_v3 *)tx_resp)->status;
}

/**
 * iwl_fmac_get_scd_ssn - returns the SSN of the SCD
 * @tx_resp: the Tx response from the fw (agg or non-agg)
 *
 * When the fw sends an AMPDU, it fetches the MPDUs one after the other. Since
 * it can't know that everything will go well until the end of the AMPDU, it
 * can't know in advance the number of MPDUs that will be sent in the current
 * batch. This is why it writes the agg Tx response while it fetches the MPDUs.
 * Hence, it can't know in advance what the SSN of the SCD will be at the end
 * of the batch. This is why the SSN of the SCD is written at the end of the
 * whole struct at a variable offset. This function knows how to cope with the
 * variable offset and returns the SSN of the SCD.
 */
static u32 iwl_fmac_get_scd_ssn(struct iwl_fmac *fmac,
				struct iwl_mvm_tx_resp *tx_resp)
{
	return le32_to_cpup((__le32 *)iwl_fmac_get_agg_status(fmac, tx_resp) +
			    tx_resp->frame_count) & 0xfff;
}

static void iwl_fmac_update_sta_tx_stats(struct iwl_fmac *fmac,
					 struct iwl_mvm_tx_resp *tx_resp)
{
	struct iwl_fmac_sta *sta;
	struct iwl_fmac_tx_stats *stats;
	int sta_id = IWL_MVM_TX_RES_GET_RA(tx_resp->ra_tid);
	u32 status =
		le16_to_cpu(iwl_fmac_get_agg_status(fmac, tx_resp)->status);

	rcu_read_lock();
	sta = rcu_dereference(fmac->stas[sta_id]);
	if (unlikely(!sta)) {
		rcu_read_unlock();
		return;
	}

	stats = &sta->info.tx_stats;
	stats->last_rate = le32_to_cpu(tx_resp->initial_rate);
	stats->bytes += le16_to_cpu(tx_resp->byte_cnt);
	stats->packets += tx_resp->frame_count;
	if (tx_resp->frame_count == 1) {
		stats->retries += tx_resp->failure_frame;
		if (!(status & TX_STATUS_SUCCESS ||
		      status & TX_STATUS_DIRECT_DONE))
			stats->failed++;
	}
	rcu_read_unlock();
}

static void iwl_fmac_rx_tx_cmd_single(struct iwl_fmac *fmac,
				      struct iwl_rx_packet *pkt)
{
	u16 sequence = le16_to_cpu(pkt->hdr.sequence);
	int txq_id = SEQ_TO_QUEUE(sequence);
	/* struct iwl_mvm_tx_resp_v3 is almost the same */
	struct iwl_mvm_tx_resp *tx_resp = (void *)pkt->data;
	int sta_id = IWL_MVM_TX_RES_GET_RA(tx_resp->ra_tid);
	int tid = IWL_MVM_TX_RES_GET_TID(tx_resp->ra_tid);
	u32 status;
	u16 ssn = iwl_fmac_get_scd_ssn(fmac, tx_resp);
	bool ack;

	status = le16_to_cpu(iwl_fmac_get_agg_status(fmac, tx_resp)->status);
	ack = (status & TX_STATUS_MSK) == TX_STATUS_SUCCESS;

	if (iwl_fmac_has_new_tx_api(fmac))
		txq_id = le16_to_cpu(tx_resp->tx_queue);

	iwl_fmac_reclaim_and_free(fmac, sta_id, tid, txq_id, ssn, ack);

	IWL_DEBUG_TX_REPLY(fmac, "TXQ %d status 0x%08x\n", txq_id, status);

	IWL_DEBUG_TX_REPLY(fmac,
			   "\t\t\t\tinitial_rate 0x%x retries %d, idx=%d ssn=%d\n",
			   le32_to_cpu(tx_resp->initial_rate),
			   tx_resp->failure_frame, SEQ_TO_INDEX(sequence),
			   ssn);
}

void iwl_fmac_rx_tx_cmd(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mvm_tx_resp *tx_resp = (void *)pkt->data;

	if (tx_resp->frame_count == 1)
		iwl_fmac_rx_tx_cmd_single(fmac, pkt);

	/* Ignore aggregated TX responses. They only carry data
	 * for TLC which is now offloaded.
	 */

	iwl_fmac_update_sta_tx_stats(fmac, tx_resp);
}

static void
iwl_fmac_update_sta_ba_tx_stats(struct iwl_fmac *fmac,
				struct iwl_mvm_compressed_ba_notif *notif)
{
	struct iwl_fmac_sta *sta;
	struct iwl_fmac_tx_stats *stats;

	rcu_read_lock();
	sta = rcu_dereference(fmac->stas[notif->sta_id]);
	if (unlikely(!sta)) {
		rcu_read_unlock();
		return;
	}

	stats = &sta->info.tx_stats;
	stats->last_rate = le32_to_cpu(notif->tx_rate);
	stats->bytes += le32_to_cpu(notif->query_byte_cnt);
	stats->packets += le16_to_cpu(notif->query_frame_cnt);
	stats->retries += notif->retry_cnt;
	rcu_read_unlock();
}

void iwl_fmac_rx_ba_notif(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_mvm_ba_notif *ba_notif;
	u16 scd_flow;
	u16 scd_ssn;

	if (iwl_fmac_has_new_tx_api(fmac)) {
		struct iwl_mvm_compressed_ba_notif *ba_res = (void *)pkt->data;
		int i;

		for (i = 0; i < le16_to_cpu(ba_res->tfd_cnt); i++) {
			u8 tid;
			u16 queue;
			u16 tfd_idx;

			tid = ba_res->tfd[i].tid;
			if (tid == IWL_MGMT_TID)
				tid = IWL_MAX_TID_COUNT;
			queue = le16_to_cpu(ba_res->tfd[i].q_num);
			tfd_idx = le16_to_cpu(ba_res->tfd[i].tfd_index);

			/*
			 * Assume the frame was ACKed, we don't send
			 * mgmt frames in AMPDU anyway.
			 */
			iwl_fmac_reclaim_and_free(fmac, ba_res->sta_id, tid,
						  queue, tfd_idx, true);
		}

		if (i > 0)
			iwl_fmac_update_sta_ba_tx_stats(fmac, ba_res);

		IWL_DEBUG_TX_REPLY(fmac,
				   "BA_NOTIFICATION Received from sta_id = %d, flags %x, sent:%d, acked:%d\n",
				   ba_res->sta_id, le32_to_cpu(ba_res->flags),
				   le16_to_cpu(ba_res->txed),
				   le16_to_cpu(ba_res->done));

		return;
	}

	ba_notif = (void *)pkt->data;
	scd_ssn = le16_to_cpu(ba_notif->scd_ssn);
	scd_flow = le16_to_cpu(ba_notif->scd_flow);

	/*
	 * Assume the frame was ACKed, we don't send
	 * mgmt frames in AMPDU anyway.
	 */
	iwl_fmac_reclaim_and_free(fmac, ba_notif->sta_id, ba_notif->tid,
				  scd_flow, scd_ssn, true);

	IWL_DEBUG_TX_REPLY(fmac, "ba_notif from %pM, sta_id = %d\n",
			   ba_notif->sta_addr, ba_notif->sta_id);
	IWL_DEBUG_TX_REPLY(fmac, "tid %d, seq %d, bitmap 0x%llx, scd flow %d, ssn %d, sent %d, acked %d\n",
			   ba_notif->tid, le16_to_cpu(ba_notif->seq_ctl),
			   (unsigned long long)le64_to_cpu(ba_notif->bitmap),
			   scd_flow, scd_ssn, ba_notif->txed,
			   ba_notif->txed_2_done);
}

static u8 iwl_fmac_bt_coex_tx_prio(struct iwl_fmac *fmac,
				   struct ieee80211_hdr *hdr, u8 ac)
{
	/* TODO: make sure that LMAC ignore those in case we operate in 5GHz */

	if (unlikely(is_multicast_ether_addr(hdr->addr1)))
		return 3;

	switch (ac) {
	case AC_BE:
		return 01;
	case AC_VI:
		return 2;
	case AC_VO:
		return 3;
	default:
		return 0;
	}

	return 0;
}

static u16 iwl_fmac_tx_csum(struct iwl_fmac *fmac, struct sk_buff *skb,
			    struct ieee80211_hdr *hdr,
			    struct iwl_fmac_tx_data *tx,
			    u16 offload_assist)
{
#if IS_ENABLED(CONFIG_INET)
	u16 mh_len = ieee80211_hdrlen(hdr->frame_control);

	if (iwl_fmac_csum_prepare(fmac, skb))
		return offload_assist;

	/* enable L4 csum */
	offload_assist |= BIT(TX_CMD_OFFLD_L4_EN);

	/*
	 * Set offset to IP header (snap).
	 * We don't support tunneling so no need to take care of inner header.
	 * Size is in words.
	 */
	offload_assist |= (4 << TX_CMD_OFFLD_IP_HDR);

	/* Do IPv4 csum only (no IP csum for Ipv6) */
	if (skb->protocol == htons(ETH_P_IP))
		offload_assist |= BIT(TX_CMD_OFFLD_L3_EN);

	/*
	 * mac header len should include IV, unless the IV is added by the
	 * firmware like in WEP.
	 * In new Tx API, the IV is always added by the firmware.
	 */
	if (!iwl_fmac_has_new_tx_api(fmac) && tx->key &&
	    tx->key->cipher != IWL_FMAC_CIPHER_WEP40 &&
	    tx->key->cipher != IWL_FMAC_CIPHER_WEP104)
		mh_len += tx->key->iv_len;
	mh_len /= 2;
	offload_assist |= mh_len << TX_CMD_OFFLD_MH_SIZE;
#endif
	return offload_assist;
}

/*
 * Sets most of the Tx cmd's fields
 */
static void iwl_fmac_set_tx_cmd(struct iwl_fmac *fmac, struct sk_buff *skb,
				struct iwl_tx_cmd *tx_cmd,
				struct iwl_fmac_tx_data *tx)
{
	struct ieee80211_hdr *hdr = (void *)skb->data;
	__le16 fc = hdr->frame_control;
	u32 tx_flags = le32_to_cpu(tx_cmd->tx_flags);
	u32 len = skb->len + FCS_LEN;
	u16 offload_assist = 0;
	u8 ac;

	if (ieee80211_is_probe_resp(fc))
		tx_flags |= TX_CMD_FLG_TSF;

	if (ieee80211_has_morefrags(fc))
		tx_flags |= TX_CMD_FLG_MORE_FRAG;

	if (ieee80211_is_data_qos(fc)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);

		tx_cmd->tid_tspec = qc[0] & 0xf;
		if (*qc & IEEE80211_QOS_CTL_A_MSDU_PRESENT)
			offload_assist |= BIT(TX_CMD_OFFLD_AMSDU);
	} else {
		if (ieee80211_is_data(fc))
			tx_cmd->tid_tspec = IWL_TID_NON_QOS;
		else
			tx_cmd->tid_tspec = IWL_MAX_TID_COUNT;

		tx_flags |= TX_CMD_FLG_SEQ_CTL;
	}

	/* Default to 0 (BE) when tid_spec is set to IWL_TID_NON_QOS */
	if (tx_cmd->tid_tspec < IWL_MAX_TID_COUNT)
		ac = tid_to_ac[tx_cmd->tid_tspec];
	else
		ac = tid_to_ac[0];

	tx_flags |= iwl_fmac_bt_coex_tx_prio(fmac, hdr, ac) <<
		TX_CMD_FLG_BT_PRIO_POS;

	if (ieee80211_is_data(fc) && len > fmac->rts_threshold &&
	    !is_multicast_ether_addr(hdr->addr1))
		tx_flags |= TX_CMD_FLG_PROT_REQUIRE;

	/* TODO: check additional conditions when no ack required */
	if (!is_multicast_ether_addr(hdr->addr1))
		tx_flags |= TX_CMD_FLG_ACK;

	tx_cmd->tx_flags = cpu_to_le32(tx_flags);
	/* Total # bytes to be transmitted */
	tx_cmd->len = cpu_to_le16((u16)skb->len);
	tx_cmd->life_time = cpu_to_le32(TX_CMD_LIFE_TIME_INFINITE);
	tx_cmd->sta_id = tx->sta->sta_id;

	/* padding is inserted later in transport */
	if (ieee80211_hdrlen(fc) % 4 &&
	    !(offload_assist & BIT(TX_CMD_OFFLD_AMSDU)))
		offload_assist |= BIT(TX_CMD_OFFLD_PAD);

	tx_cmd->offload_assist =
		cpu_to_le16(iwl_fmac_tx_csum(fmac, skb, hdr, tx,
					     offload_assist));
}

/*
 * Sets the fields in the Tx cmd that are rate related
 */
static void iwl_fmac_set_tx_cmd_rate(struct iwl_fmac *fmac,
				     struct iwl_tx_cmd *tx_cmd,
				     struct iwl_fmac_tx_data *tx, __le16 fc)
{
	/* Set retry limit on RTS packets */
	tx_cmd->rts_retry_limit = IWL_RTS_DFAULT_RETRY_LIMIT;

	/* Set retry limit on DATA packets and Probe Responses*/
	tx_cmd->data_retry_limit = IWL_DEFAULT_TX_RETRY;

	/*
	 * for data packets, rate info comes from the table inside the fw. This
	 * table is controlled by LINK_QUALITY commands
	 */

	if (ieee80211_is_data(fc) && tx->sta) {
		tx_cmd->initial_rate_index = 0;
		tx_cmd->tx_flags |= cpu_to_le32(TX_CMD_FLG_STA_RATE);
		return;
	}

	/* Set retry limit on DATA packets and Probe Responses*/
	if (ieee80211_is_probe_resp(fc)) {
		tx_cmd->data_retry_limit = IWL_MGMT_DFAULT_RETRY_LIMIT;
		tx_cmd->rts_retry_limit =
			min(tx_cmd->data_retry_limit, tx_cmd->rts_retry_limit);
	}

	if (tx->flags & IWL_FMAC_SKB_INFO_FLAG_BAND_5 ||
	    tx->flags & IWL_FMAC_SKB_INFO_FLAG_NO_CCK)
		tx_cmd->rate_n_flags = cpu_to_le32(IWL_RATE_6M_PLCP);
	else
		tx_cmd->rate_n_flags =
			cpu_to_le32(IWL_RATE_1M_PLCP | RATE_MCS_CCK_MSK);

	/* TODO switch antenna */
	tx_cmd->rate_n_flags |= cpu_to_le32(RATE_MCS_ANT_A_MSK);
}

/*
 * Sets the fields in the Tx cmd that are crypto related
 */
static void iwl_fmac_set_crypto(struct sk_buff *skb,
				struct iwl_tx_cmd *tx_cmd,
				struct iwl_fmac_tx_data *tx,
				int hdrlen)
{
	struct iwl_fmac_sta_key *key = tx->key;

	if (!key)
		return;

	switch (key->cipher) {
	case IWL_FMAC_CIPHER_GCMP:
	case IWL_FMAC_CIPHER_GCMP_256:
		tx_cmd->sec_ctl |= TX_CMD_SEC_GCMP | TX_CMD_SEC_KEY_FROM_TABLE;
		tx_cmd->key[0] = key->hw_keyidx;
		break;
	case IWL_FMAC_CIPHER_CCMP:
	case IWL_FMAC_CIPHER_CCMP_256:
		tx_cmd->sec_ctl |= TX_CMD_SEC_CCM | TX_CMD_SEC_KEY_FROM_TABLE;
		tx_cmd->key[0] = key->hw_keyidx;
		break;
	case IWL_FMAC_CIPHER_WEP40:
	case IWL_FMAC_CIPHER_WEP104:
		tx_cmd->sec_ctl |= TX_CMD_SEC_WEP | TX_CMD_SEC_KEY_FROM_TABLE |
			((key->keyidx << TX_CMD_SEC_WEP_KEY_IDX_POS) &
			  TX_CMD_SEC_WEP_KEY_IDX_MSK);
		tx_cmd->key[0] = key->hw_keyidx;
		break;
	case IWL_FMAC_CIPHER_TKIP:
		tx_cmd->sec_ctl |= TX_CMD_SEC_TKIP | TX_CMD_SEC_KEY_FROM_TABLE;
		tx_cmd->key[0] = key->hw_keyidx;
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

/*
 * Allocates and sets the Tx cmd the driver data pointers in the skb
 */
static struct iwl_device_cmd *
iwl_fmac_set_tx_params(struct iwl_fmac *fmac, struct sk_buff *skb,
		       struct iwl_fmac_skb_info *info, int hdrlen
,		       struct iwl_fmac_tx_data *tx)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct iwl_device_cmd *dev_cmd;

	if (info->dev_cmd)
		return info->dev_cmd;

	dev_cmd = iwl_trans_alloc_tx_cmd(fmac->trans);

	if (unlikely(!dev_cmd))
		return NULL;

	memset(dev_cmd, 0, sizeof(*dev_cmd));
	dev_cmd->hdr.cmd = TX_CMD;

	if (iwl_fmac_has_new_tx_api(fmac)) {
		u32 offload_assist = 0;
		bool amsdu = false;

		if (ieee80211_is_data_qos(hdr->frame_control)) {
			u8 *qc = ieee80211_get_qos_ctl(hdr);

			if (*qc & IEEE80211_QOS_CTL_A_MSDU_PRESENT) {
				offload_assist |= BIT(TX_CMD_OFFLD_AMSDU);
				amsdu = true;
			}
		}

		if (ieee80211_hdrlen(hdr->frame_control) % 4 && !amsdu)
			offload_assist |= BIT(TX_CMD_OFFLD_PAD);

		offload_assist = iwl_fmac_tx_csum(fmac, skb, hdr, tx,
						  offload_assist);

		if (fmac->trans->cfg->device_family >=
		    IWL_DEVICE_FAMILY_22560) {
			struct iwl_tx_cmd_gen3 *tx_cmd =
				(void *)dev_cmd->payload;

			tx_cmd->offload_assist = cpu_to_le32(offload_assist);
			tx_cmd->len = cpu_to_le16(skb->len);
			memcpy(tx_cmd->hdr, hdr, hdrlen);
		} else {
			struct iwl_tx_cmd_gen2 *tx_cmd =
				(void *)dev_cmd->payload;

			tx_cmd->offload_assist = cpu_to_le16(offload_assist);
			tx_cmd->len = cpu_to_le16(skb->len);
			memcpy(tx_cmd->hdr, hdr, hdrlen);
		}
	} else {
		struct iwl_tx_cmd *tx_cmd = (void *)dev_cmd->payload;

		iwl_fmac_set_crypto(skb, tx_cmd, tx,
				    ieee80211_hdrlen(hdr->frame_control));

		iwl_fmac_set_tx_cmd(fmac, skb, tx_cmd, tx);

		iwl_fmac_set_tx_cmd_rate(fmac, tx_cmd, tx,
					 hdr->frame_control);

		/* TODO: we'll need more stuff here */
	}

	info->dev_cmd = dev_cmd;

	return dev_cmd;
}

static int iwl_fmac_tx_mpdu(struct iwl_fmac *fmac, struct sk_buff *skb,
			    struct iwl_fmac_tx_data *tx,
			    struct iwl_fmac_skb_info *info)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct iwl_fmac_sta *sta = tx->sta;
	struct iwl_device_cmd *dev_cmd;
	__le16 fc;
	u16 seq_number = 0;
	u8 tid = 0; /* If no TID is given - use TID 0 */
	u16 txq_id;
	int hdrlen;

	if (WARN_ON_ONCE(!sta))
		return -1;

	if (WARN_ON_ONCE(sta->sta_id == IWL_FMAC_STATION_COUNT))
		return -1;

	fc = hdr->frame_control;
	hdrlen = ieee80211_hdrlen(fc);

	dev_cmd = iwl_fmac_set_tx_params(fmac, skb, info, hdrlen, tx);
	if (!dev_cmd)
		goto drop;

	spin_lock(&sta->lock);

	if (ieee80211_is_data_qos(fc)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);

		tid = qc[0] & IEEE80211_QOS_CTL_TID_MASK;
		if (WARN_ON_ONCE(tid >= IWL_MAX_TID_COUNT))
			goto drop_unlock_sta;

		seq_number = sta->tids[tid].seq_number;
		seq_number &= IEEE80211_SCTL_SEQ;
		hdr->seq_ctrl &= cpu_to_le16(IEEE80211_SCTL_FRAG);
		hdr->seq_ctrl |= cpu_to_le16(seq_number);
		/* TODO: check for AMPDU flag */
	}

	txq_id = sta->tids[tid].txq_id;

	/* TODO: TDLS - default to TID 0 for non-QoS packets */

	/* Check if TXQ needs to be allocated */
	if (unlikely(txq_id == IWL_FMAC_INVALID_TXQ_ID)) {
		/* This is a bit hacky - we hold a pointer to the station
		 * which is an RCU protected pointer and enqueue the skb
		 * for later processing. This is fine though since if the
		 * station were to be destroyed, it'd destroy the queue as
		 * well and hence the skb would be freed.
		 */
		iwl_fmac_tx_add_stream(fmac, sta, tid, skb);

		spin_unlock(&sta->lock);

		/* TODO: handle DQA inactive queue re-activations */

		return 0;
	}

	/*
	 * TODO: Keep track of the time of the last frame for this RA/TID for
	 * timeouts and freeing queues
	 */

	/* Copy MAC header from skb into command buffer */
	if (fmac->trans->cfg->device_family >=
	    IWL_DEVICE_FAMILY_22560) {
		struct iwl_tx_cmd_gen3 *tx_cmd = (void *)dev_cmd->payload;

		memcpy(tx_cmd->hdr, hdr, hdrlen);
	} else if (iwl_fmac_has_new_tx_api(fmac)) {
		struct iwl_tx_cmd_gen2 *tx_cmd = (void *)dev_cmd->payload;

		memcpy(tx_cmd->hdr, hdr, hdrlen);
		if (tx->key && tx->key->cipher == IWL_FMAC_CIPHER_TKIP) {
			skb_put_zero(skb, MICHAEL_MIC_LEN);
			le16_add_cpu(&tx_cmd->len, MICHAEL_MIC_LEN);
		}
	} else {
		struct iwl_tx_cmd *tx_cmd = (void *)dev_cmd->payload;

		memcpy(tx_cmd->hdr, hdr, hdrlen);
	}

	IWL_DEBUG_TX(fmac, "TX to [%d|%d] Q:%d - seq: 0x%x\n", sta->sta_id,
		     tid, txq_id, IEEE80211_SEQ_TO_SN(seq_number));

	if (iwl_trans_tx(fmac->trans, skb, dev_cmd, txq_id))
		goto drop_unlock_sta;

	if (ieee80211_is_data_qos(fc) && !ieee80211_has_morefrags(fc))
		sta->tids[tid].seq_number = seq_number + 0x10;

	spin_unlock(&sta->lock);

	/* TODO: Increase pending frames count if this isn't AMPDU */

	/* TODO: keep count of pending frames */

	return 0;

drop_unlock_sta:
	iwl_trans_free_tx_cmd(fmac->trans, dev_cmd);
	spin_unlock(&sta->lock);
drop:
	return -1;
}

#ifdef CONFIG_INET
static int
iwl_fmac_tx_segment(struct sk_buff *skb, unsigned int num_subframes,
		    netdev_features_t netdev_flags,
		    struct sk_buff_head *mpdus_skb)
{
	struct sk_buff *tmp, *next;
	struct ieee80211_hdr *hdr = (void *)skb->data;
	char cb[sizeof(skb->cb)];
	unsigned int payload;
	unsigned int mss = skb_shinfo(skb)->gso_size;
	bool ipv4 = (skb->protocol == htons(ETH_P_IP));
	u16 ip_base_id = ipv4 ? ntohs(ip_hdr(skb)->id) : 0, i = 0;

	skb_shinfo(skb)->gso_size = num_subframes * mss;
	memcpy(cb, skb->cb, sizeof(cb));

	next = skb_gso_segment(skb, netdev_flags);
	skb_shinfo(skb)->gso_size = mss;
	if (WARN_ON_ONCE(IS_ERR(next)))
		return -EINVAL;
	else if (next)
		consume_skb(skb);

	while (next) {
		tmp = next;
		next = tmp->next;

		memcpy(tmp->cb, cb, sizeof(tmp->cb));
		/*
		 * Compute the length of all the data added for the A-MSDU.
		 * This will be used to compute the length to write in the TX
		 * command. We have: SNAP + IP + TCP for n -1 subframes and
		 * ETH header for n subframes.
		 */
		payload = skb_tail_pointer(tmp) - skb_transport_header(tmp) -
			tcp_hdrlen(tmp) + tmp->data_len;

		if (ipv4)
			ip_hdr(tmp)->id = htons(ip_base_id + i * num_subframes);

		if (payload > mss) {
			skb_shinfo(tmp)->gso_size = mss;
		} else {
			if (ieee80211_is_data_qos(hdr->frame_control)) {
				u8 *qc;

				if (ipv4)
					ip_send_check(ip_hdr(tmp));

				qc = ieee80211_get_qos_ctl((void *)tmp->data);
				*qc &= ~IEEE80211_QOS_CTL_A_MSDU_PRESENT;
			}
			skb_shinfo(tmp)->gso_size = 0;
		}

		tmp->prev = NULL;
		tmp->next = NULL;

		__skb_queue_tail(mpdus_skb, tmp);
		i++;
	}

	return 0;
}
#endif

static int iwl_fmac_tx_tso(struct iwl_fmac *fmac, struct sk_buff *skb,
			   struct iwl_fmac_tx_data *tx,
			   struct sk_buff_head *mpdus_skb)
{
#ifdef CONFIG_INET
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	struct iwl_fmac_sta *sta = tx->sta;
	netdev_features_t netdev_flags = NETIF_F_CSUM_MASK | NETIF_F_SG;
	unsigned int subframes, tcp_payload_len, subf_len, max_len;
	unsigned int mss = skb_shinfo(skb)->gso_size;
	u16 pad;
	u8 tid;

	if (!ieee80211_is_data_qos(hdr->frame_control) ||
	    !sta->amsdu_size || !sta->amsdu_enabled ||
	    (tx->key && tx->key->cipher == IWL_FMAC_CIPHER_TKIP))
		return iwl_fmac_tx_segment(skb, 1, netdev_flags, mpdus_skb);

	/*
	 * Do not build AMSDU for IPv6 with extension headers.
	 * Ask stack to segment and checkum the generated MPDUs for us.
	 */
	if (skb->protocol == htons(ETH_P_IPV6) &&
	    ((struct ipv6hdr *)skb_network_header(skb))->nexthdr !=
	    IPPROTO_TCP) {
		netdev_flags &= ~NETIF_F_CSUM_MASK;
		return iwl_fmac_tx_segment(skb, 1, netdev_flags, mpdus_skb);
	}

	tid = *ieee80211_get_qos_ctl(hdr) & IEEE80211_QOS_CTL_TID_MASK;
	if (WARN_ON_ONCE(tid >= IWL_MAX_TID_COUNT))
		return -EINVAL;

	max_len = iwl_fmac_max_amsdu_size(fmac, sta, tid);

	/* Sub frame header + SNAP + IP header + TCP header + MSS */
	subf_len = sizeof(struct ethhdr) + 8 + skb_transport_header(skb) -
		skb_network_header(skb) + tcp_hdrlen(skb) + mss;
	pad = (4 - subf_len) & 0x3;

	/*
	 * If we have N subframes in the A-MSDU, then the A-MSDU's size is
	 * N * subf_len + (N - 1) * pad.
	 */
	subframes = (max_len + pad) / (subf_len + pad);

	/*
	 * The most severe restriction we can have on the number of subframes
	 * is 8. This can be advertised by the peer through the extended
	 * capabilities. Since we are very unlikely to reach that limit anyway
	 * don't parse the extended capability and just limit ourselves to 8.
	 */
	subframes = min_t(unsigned int, subframes, 8);

	/*
	 * Make sure we have enough TBs for the A-MSDU:
	 *	2 for each subframe
	 *	1 more for each fragment
	 *	1 more for the potential data in the header
	 */
	if ((subframes * 2 + skb_shinfo(skb)->nr_frags + 1) >
	    fmac->trans->max_skb_frags)
		subframes = 1;

	if (subframes > 1)
		*ieee80211_get_qos_ctl(hdr) |= IEEE80211_QOS_CTL_A_MSDU_PRESENT;


	tcp_payload_len = skb_tail_pointer(skb) - skb_transport_header(skb) -
		tcp_hdrlen(skb) + skb->data_len;

	/* This skb fits in one single A-MSDU */
	if (subframes * mss >= tcp_payload_len) {
		__skb_queue_tail(mpdus_skb, skb);
		return 0;
	}

	/* Use segmentation to create SKBs that can fit in an A-MSDU. */
	return iwl_fmac_tx_segment(skb, subframes, netdev_flags, mpdus_skb);
#else /* CONFIG_INET */
	/* Impossible to get TSO without CONFIG_INET */
	WARN_ON(1);
	return -1;
#endif
}

int iwl_fmac_tx_skb(struct iwl_fmac *fmac, struct sk_buff *skb,
		    struct iwl_fmac_tx_data *tx)
{
	struct iwl_fmac_skb_info *info;
	struct sk_buff_head mpdus_skbs;
	unsigned int payload_len;
	int ret;

	__skb_queue_head_init(&mpdus_skbs);

	payload_len = skb_tail_pointer(skb) - skb_transport_header(skb) -
		tcp_hdrlen(skb) + skb->data_len;

	if (!skb_is_gso(skb) || payload_len <= skb_shinfo(skb)->gso_size) {
		__skb_queue_tail(&mpdus_skbs, skb);
	} else {
		ret = iwl_fmac_tx_tso(fmac, skb, tx, &mpdus_skbs);
		if (ret)
			return ret;
	}

	if (WARN_ON(skb_queue_empty(&mpdus_skbs)))
		return -EINVAL;

	while (!skb_queue_empty(&mpdus_skbs)) {
		skb = __skb_dequeue(&mpdus_skbs);

		info = (void *)skb->cb;

		ret = iwl_fmac_tx_mpdu(fmac, skb, tx, info);
		if (ret) {
			__skb_queue_purge(&mpdus_skbs);
			return ret;
		}
	}

	return 0;
}

void iwl_fmac_tx_send_frame(struct iwl_fmac *fmac,
			    struct iwl_fmac_send_frame_notif *send_frame)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	u16 len = le16_to_cpu(send_frame->len);
	struct wireless_dev *wdev;
	struct iwl_fmac_vif *vif = NULL;
	struct sk_buff *skb;
	size_t copy_size;

	if (WARN_ON(send_frame->proto != cpu_to_be16(ETH_P_PAE)))
		return;

	rcu_read_lock();

	list_for_each_entry(wdev, &wiphy->wdev_list, list) {
		vif = vif_from_wdev(wdev);

		if (vif->id == send_frame->vif_id)
			break;
	}

	if (WARN_ON(!vif ||
		    vif->wdev.iftype != NL80211_IFTYPE_STATION))
		goto out;

	skb = alloc_skb(len + sizeof(send_frame->src_addr) +
			sizeof(send_frame->dst_addr) +
			sizeof(send_frame->proto) +
			wdev->netdev->needed_tailroom +
			wdev->netdev->needed_headroom, GFP_ATOMIC);
	if (!skb)
		goto out;

	skb_reserve(skb, wdev->netdev->needed_headroom);

	copy_size = offsetof(struct iwl_fmac_send_frame_notif, data) -
		offsetof(struct iwl_fmac_send_frame_notif, dst_addr) + len;

	memcpy(skb_put(skb, copy_size), send_frame->dst_addr, copy_size);

	iwl_fmac_dev_start_xmit(skb, wdev->netdev);

out:
	rcu_read_unlock();
}

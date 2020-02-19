/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright (C) 2018 - 2019 Intel Corporation
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
 * Copyright (C) 2018 - 2019 Intel Corporation
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
#include <linux/etherdevice.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <linux/if_arp.h>

#include "iwl-debug.h"

#include "fmac.h"

static int iwl_fmac_dev_init(struct net_device *dev)
{
	netif_carrier_off(dev);

	dev->needed_headroom += sizeof(struct ieee80211_hdr) +
				sizeof(rfc1042_header) +
				sizeof(__le16) * 4 /* qos, seq, dur, ctl */
				+ 8 /* rfc1042 tunnel */
				+ 8 /* ENCRYPT_HEADROOM */
				/* A-MSDU subframe header on first frame */
				+ sizeof(struct ethhdr);

	dev->needed_tailroom = 18 /* ENCRYPT_TAILROOM */;

	return 0;
}

static void iwl_fmac_dev_uninit(struct net_device *dev)
{
}

static int __iwl_fmac_dev_stop(struct net_device *dev)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac *fmac = vif->fmac;
	struct iwl_fmac_del_vif_cmd cmd = {
		.id = vif->id,
	};
	int ret;

	lockdep_assert_held(&fmac->mutex);

	if (fmac->scan_request &&
	    vif == vif_from_wdev(fmac->scan_request->wdev))
		iwl_fmac_abort_scan(fmac, vif);

	iwl_fmac_process_async_handlers(fmac);

	if (WARN_ON(fmac->scan_request &&
		    vif == vif_from_wdev(fmac->scan_request->wdev)))
		fmac->scan_request = NULL;

	atomic_dec(&fmac->open_count);

	ret = iwl_fmac_send_cmd_pdu(fmac, iwl_cmd_id(FMAC_DEL_VIF,
						     FMAC_GROUP, 0),
				    0, sizeof(cmd), &cmd);
	WARN_ON(ret);

	vif->id = FMAC_VIF_ID_INVALID;

	if (!atomic_read(&fmac->open_count))
		iwl_fmac_stop_device(fmac);

	return ret;
}

int iwl_fmac_nl_to_fmac_type(enum nl80211_iftype iftype)
{
	switch (iftype) {
	case NL80211_IFTYPE_STATION:
		return IWL_FMAC_IFTYPE_MGD;
	default:
		WARN(1, "Unsupported iftype %d\n", iftype);
		return -EINVAL;
	}
}

static int iwl_fmac_dev_open(struct net_device *dev)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac *fmac = vif->fmac;
	struct iwl_fmac_add_vif_cmd cmd = {};
	struct iwl_fmac_add_vif_resp *resp;
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(FMAC_ADD_VIF, FMAC_GROUP, 0),
		.flags = CMD_WANT_SKB,
		.data = { &cmd, },
		.len = { sizeof(cmd), },
	};
	int ret, i;

	mutex_lock(&fmac->mutex);

	ret = iwl_fmac_nl_to_fmac_type(vif->wdev.iftype);
	if (ret < 0)
		goto out;
	cmd.type = ret;

	/* This is the first interface to be open, load the firmware */
	if (!atomic_read(&fmac->open_count)) {
		ret = iwl_fmac_run_rt_fw(fmac);
		if (ret) {
			if (ret != -ERFKILL)
				iwl_fw_dbg_error_collect(&fmac->fwrt,
							 FW_DBG_TRIGGER_DRIVER);
			goto out;
		}
	}
	ether_addr_copy(cmd.addr, dev->dev_addr);

	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	if (ret) {
		ret = -EBUSY;
		goto out;
	}

	resp = (void *)((struct iwl_rx_packet *)hcmd.resp_pkt)->data;
	if (resp->status != IWL_ADD_VIF_SUCCESS) {
		IWL_ERR(fmac, "vif creation failed\n");
		ret = -EBUSY;
		goto out_free_resp;
	}

	atomic_inc(&fmac->open_count);
	vif->id = resp->id;

	/* set user tx power */
	iwl_fmac_send_config_u32(fmac, vif->id,
				 IWL_FMAC_CONFIG_VIF_TXPOWER_USER,
				 vif->user_power_level);

#ifdef CONFIG_THERMAL
	/* TODO: read the budget from BIOS / Platform NVM */

	/*
	 * In case there is no budget from BIOS / Platform NVM the default
	 * budget should be 2000mW (cooling state 0).
	 */
	ret = iwl_fmac_ctdp_command(fmac, CTDP_CMD_OPERATION_START,
				    fmac->cooling_dev.cur_state);
	if (ret)
		goto out_free_resp;
#endif

	iwl_dbg_tlv_time_point(&fmac->fwrt, IWL_FW_INI_TIME_POINT_POST_INIT,
			       NULL);
	iwl_dbg_tlv_time_point(&fmac->fwrt, IWL_FW_INI_TIME_POINT_PERIODIC,
			       NULL);
	ret = 0;

out_free_resp:
	iwl_free_resp(&hcmd);
out:
	if (!atomic_read(&fmac->open_count))
		iwl_fmac_stop_device(fmac);
	mutex_unlock(&fmac->mutex);

	for (i = 0; !ret && i < AC_NUM; i++)
		iwl_fmac_wake_ac_queue(fmac, &vif->wdev, i);

	return ret;
}

static int iwl_fmac_dev_stop(struct net_device *dev)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	struct iwl_fmac *fmac = vif->fmac;
	int ret, i;

	for (i = 0; i < AC_NUM; i++)
		iwl_fmac_stop_ac_queue(fmac, &vif->wdev, i);

	mutex_lock(&fmac->mutex);
	ret = __iwl_fmac_dev_stop(dev);
	mutex_unlock(&fmac->mutex);

	return ret;
}

static int iwl_fmac_dev_set_mac_address(struct net_device *dev, void *addr)
{
	if (netif_running(dev))
		return -EBUSY;

	return eth_mac_addr(dev, addr);
}

static int iwl_fmac_dev_change_mtu(struct net_device *dev, int mtu)
{
	if (mtu < 256 || mtu > IEEE80211_MAX_DATA_LEN)
		return -EINVAL;

	dev->mtu = mtu;
	return 0;
}

static void
iwl_fmac_dev_get_stats64(struct net_device *dev,
			 struct rtnl_link_stats64 *stats)
{
	unsigned int i;

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *tstats;
		u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
		unsigned int start;

		tstats = per_cpu_ptr(netdev_tstats(dev), i);

		do {
			start = u64_stats_fetch_begin_irq(&tstats->syncp);
			rx_packets = tstats->rx_packets;
			tx_packets = tstats->tx_packets;
			rx_bytes = tstats->rx_bytes;
			tx_bytes = tstats->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&tstats->syncp, start));

		stats->rx_packets += rx_packets;
		stats->tx_packets += tx_packets;
		stats->rx_bytes   += rx_bytes;
		stats->tx_bytes   += tx_bytes;
	}
}
#if LINUX_VERSION_IS_LESS(4,11,0) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,6)
static struct rtnl_link_stats64 *
bp_iwl_fmac_dev_get_stats64(struct net_device *dev,
			    struct rtnl_link_stats64 *stats){
	iwl_fmac_dev_get_stats64(dev, stats);
	return stats;
}
#endif

static const u8 iwl_fmac_downgrade[] = {2, 1, 2, 2, 3, 3, 5, 5};

static u16 iwl_fmac_select_queue(struct net_device *dev,
				 struct sk_buff *skb)
{
	struct iwl_fmac_vif *vif = vif_from_netdev(dev);
	const struct iwl_trans *trans = vif->fmac->trans;
	struct iwl_fmac_qos_map *qos_map;
	struct iwl_fmac_sta *sta = NULL;
	bool qos = false;

	if (trans->trans_cfg->base_params->num_of_queues < AC_NUM ||
	    skb->len < 6) {
		skb->priority = 0;
		return 0;
	}

	rcu_read_lock();

	switch (vif->wdev.iftype) {
	case NL80211_IFTYPE_STATION:
		sta = rcu_dereference(vif->u.mgd.ap_sta);
		if (!sta)
			IWL_DEBUG_TX(vif->fmac,
				     "AP station not initialized\n");
		break;
	default:
		break;
	}

	if (sta && sta->qos)
		qos = true;

	if (qos) {
		qos_map = rcu_dereference(vif->qos_map);
		skb->priority = cfg80211_classify8021d(skb, qos_map ?
						       &qos_map->qos_map :
						       NULL);

		if (vif->wdev.iftype == NL80211_IFTYPE_STATION) {
			while (BIT(skb->priority) & vif->u.mgd.wmm_acm) {
				skb->priority =
					iwl_fmac_downgrade[skb->priority];

				if (iwl_fmac_tid_to_tx_fifo[skb->priority] ==
				    IWL_FMAC_TX_FIFO_BK)
					break;
			}
		}

		if (skb->priority == IWL_FMAC_RESERVED_TID ||
		    WARN_ON(skb->priority >=
			    ARRAY_SIZE(iwl_fmac_tid_to_tx_fifo)))
			skb->priority = 5;

	} else {
		skb->priority = 0;
	}

	rcu_read_unlock();
	return iwl_fmac_tid_to_tx_fifo[skb->priority];
}

#if LINUX_VERSION_IS_GEQ(5,2,0)
static u16 iwl_fmac_netdev_select_queue(struct net_device *dev,
					struct sk_buff *skb,
					struct net_device *sb_dev)
#elif LINUX_VERSION_IS_GEQ(4,19,0)
static u16 iwl_fmac_netdev_select_queue(struct net_device *dev,
					struct sk_buff *skb,
					struct net_device *sb_dev,
					select_queue_fallback_t fallback)
#elif LINUX_VERSION_IS_GEQ(3,14,0) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(3,13,11) && UTS_UBUNTU_RELEASE_ABI > 30) || \
	RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,6)
static u16 iwl_fmac_netdev_select_queue(struct net_device *dev,
					struct sk_buff *skb,
					void *accel_priv,
					select_queue_fallback_t fallback)
#elif LINUX_VERSION_IS_GEQ(3,13,0)
static u16 iwl_fmac_netdev_select_queue(struct net_device *dev,
					struct sk_buff *skb,
					void *accel_priv)
#else
static u16 iwl_fmac_netdev_select_queue(struct net_device *dev,
					struct sk_buff *skb)
#endif
{
	return iwl_fmac_select_queue(dev, skb);
}

static const struct net_device_ops iwl_fmac_dev_ops = {
	.ndo_init = iwl_fmac_dev_init,
	.ndo_uninit = iwl_fmac_dev_uninit,
	.ndo_open = iwl_fmac_dev_open,
	.ndo_stop = iwl_fmac_dev_stop,
	.ndo_start_xmit = iwl_fmac_dev_start_xmit,
	.ndo_select_queue = iwl_fmac_netdev_select_queue,
	/* .ndo_set_rx_mode (for multicast filter) */
	.ndo_set_mac_address = iwl_fmac_dev_set_mac_address,
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,6)
	.ndo_change_mtu = iwl_fmac_dev_change_mtu,
#else
	.ndo_change_mtu_rh74 = iwl_fmac_dev_change_mtu,
#endif
#if LINUX_VERSION_IS_GEQ(4,11,0) || \
	RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,6)
	.ndo_get_stats64 = iwl_fmac_dev_get_stats64,
#else
	.ndo_get_stats64 = bp_iwl_fmac_dev_get_stats64,
#endif
};

static void iwl_fmac_free_netdev(struct net_device *dev)
{
	free_percpu(netdev_tstats(dev));
}

#if LINUX_VERSION_IS_LESS(4,12,0)
static void __iwl_fmac_free_netdev(struct net_device *ndev){
	iwl_fmac_free_netdev(ndev);
	free_netdev(ndev);
}
#endif

static void iwl_fmac_iface_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->netdev_ops = &iwl_fmac_dev_ops;
	netdev_set_priv_destructor(dev, iwl_fmac_free_netdev);
}

static int iwl_find_unused_mac_address(struct iwl_fmac *fmac)
{
	struct wiphy *wiphy = wiphy_from_fmac(fmac);
	struct wireless_dev *wdev;
	int i;

	for (i = 0; i < wiphy->n_addresses; i++) {
		u8 *addr = fmac->addresses[i].addr;
		bool used = false;

		rcu_read_lock();

		list_for_each_entry_rcu(wdev, &wiphy->wdev_list, list) {
			struct iwl_fmac_vif *fmac_vif = vif_from_wdev(wdev);

			if (ether_addr_equal(addr, fmac_vif->addr)) {
				used = true;
				break;
			}
		}

		rcu_read_unlock();

		if (!used)
			return i;
	}

	return -ENOMEM;
}

struct net_device *iwl_fmac_create_netdev(struct iwl_fmac *fmac,
					  const char *name,
					  unsigned char name_assign_type,
					  enum nl80211_iftype iftype,
					  struct vif_params *params)
{
	struct net_device *dev;
	const struct iwl_trans *trans = fmac->trans;
	struct iwl_fmac_vif *vif;
	int ret, addr_idx;
	int txqs = 1;
	int i;

	if (trans->trans_cfg->base_params->num_of_queues >= AC_NUM)
		txqs = AC_NUM;

	dev = alloc_netdev_mqs(sizeof(struct iwl_fmac_vif),
			       name, name_assign_type,
			       iwl_fmac_iface_setup, txqs, 1);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev_net_set(dev, wiphy_net(wiphy_from_fmac(fmac)));
	netdev_assign_tstats(dev,
			     netdev_alloc_pcpu_stats(struct pcpu_sw_netstats));
	if (!netdev_tstats(dev)) {
		free_netdev(dev);
		return ERR_PTR(-ENOMEM);
	}

	/* dev->needed_headroom = ? */

	ret = dev_alloc_name(dev, dev->name);
	if (ret < 0) {
		iwl_fmac_free_netdev(dev);
		return ERR_PTR(ret);
	}

	vif = vif_from_netdev(dev);
	vif->wdev.wiphy = wiphy_from_fmac(fmac);
	vif->wdev.iftype = iftype;
	vif->fmac = fmac;
	for (i = 0; i < txqs; i++)
		__skb_queue_head_init(&vif->pending_skbs[i]);

	hrtimer_init(&vif->amsdu_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_SOFT);
	vif->amsdu_timer.function = iwl_fmac_amsdu_xmit_timer;

	vif->id = FMAC_VIF_ID_INVALID;
	dev->ieee80211_ptr = &vif->wdev;
	SET_NETDEV_DEV(dev, wiphy_dev(wiphy_from_fmac(fmac)));

	if (iftype == NL80211_IFTYPE_MONITOR)
		dev->type = ARPHRD_IEEE80211_RADIOTAP;

	addr_idx = iwl_find_unused_mac_address(fmac);
	if (addr_idx < 0) {
		iwl_fmac_free_netdev(dev);
		return ERR_PTR(addr_idx);
	}

	ether_addr_copy(dev->perm_addr, fmac->addresses[addr_idx].addr);
	ether_addr_copy(vif->addr, fmac->addresses[addr_idx].addr);

	if (params && is_valid_ether_addr(params->macaddr))
		ether_addr_copy(dev->dev_addr, params->macaddr);
	else
		ether_addr_copy(dev->dev_addr, dev->perm_addr);

	dev->features |= fmac->trans->cfg->features;

	if (!fw_has_capa(&fmac->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_CSUM_SUPPORT))
		dev->features &= ~(IWL_TX_CSUM_NETIF_FLAGS | NETIF_F_RXCSUM);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	if (fmac->trans->max_skb_frags)
		dev->features |= NETIF_F_HIGHDMA | NETIF_F_SG;
#endif

	vif->user_power_level = fmac->user_power_level;

	ret = register_netdevice(dev);
	if (ret) {
		iwl_fmac_free_netdev(dev);
		return ERR_PTR(ret);
	}

	return dev;
}

void iwl_fmac_destroy_vif(struct iwl_fmac_vif *vif)
{
	if (vif->wdev.netdev) {
		unregister_netdevice(vif->wdev.netdev);
		hrtimer_cancel(&vif->amsdu_timer);
	} else {
		cfg80211_unregister_wdev(&vif->wdev);
		kfree(vif);
	}
}

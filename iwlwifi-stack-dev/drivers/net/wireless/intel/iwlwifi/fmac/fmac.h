/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 * Copyright (C) 2018-2021 Intel Corporation
 */
#ifndef __IWL_FMAC_H__
#define __IWL_FMAC_H__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>
#include <linux/etherdevice.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <net/cfg80211.h>

#ifdef CONFIG_THERMAL
#include <linux/thermal.h>
#endif

#include "iwl-op-mode.h"
#include "iwl-trans.h"
#include "fw/notif-wait.h"
#include "fw-api.h"
#include "fw/runtime.h"
#include "fw/dbg.h"
#include "iwl-nvm-parse.h"

extern const u8 tid_to_ac[];

#define IWL_FMAC_RESERVED_TID	4
#define IWL_FMAC_INVALID_TXQ_ID	0xffff
struct iwl_fmac_tid {
	struct sk_buff_head deferred_tx_frames;
	u16 seq_number;
	u16 next_reclaimed;
	u16 txq_id;
};

/**
 * struct iwl_fmac_reorder_buffer - per ra/tid/queue reorder buffer
 * @head_sn: reorder window head sn
 * @num_stored: number of mpdus stored in the buffer
 * @buf_size: the reorder buffer size as set by the last addba request
 * @sta_id: sta id of this reorder buffer
 * @queue: queue of this reorder buffer
 * @last_amsdu: track last ASMDU SN for duplication detection
 * @last_sub_index: track ASMDU sub frame index for duplication detection
 * @entries: list of skbs stored
 * @reorder_time: time the packet was stored in the reorder buffer
 * @reorder_timer: timer for frames are in the reorder buffer. For AMSDU
 *	it is the time of last received sub-frame
 * @lock: protect reorder buffer internal state
 * @fmac: fmac pointer, needed for frame timer context
 */
struct iwl_fmac_reorder_buffer {
	struct iwl_fmac *fmac;
	u16 head_sn;
	u16 num_stored;
	u8 buf_size;
	u8 sta_id;
	int queue;
	u16 last_amsdu;
	u8 last_sub_index;
	struct sk_buff_head entries[IEEE80211_MAX_AMPDU_BUF_HE];
	unsigned long reorder_time[IEEE80211_MAX_AMPDU_BUF_HE];
	struct timer_list reorder_timer;
	spinlock_t lock; /* protect reorder buffer internal state */
} ____cacheline_aligned_in_smp;

/**
 * struct iwl_fmac_rxq_dup_data - per station per rx queue data
 * @last_seq: last sequence per tid for duplicate packet detection
 * @last_sub_frame: last subframe packet
 */
struct iwl_fmac_rxq_dup_data {
	__le16 last_seq[IWL_MAX_TID_COUNT + 1];
	u8 last_sub_frame[IWL_MAX_TID_COUNT + 1];
} ____cacheline_aligned_in_smp;

struct iwl_fmac_tkip_tsc {
	u32 iv32;
	u16 iv16;
};

#define IWL_TKIP_MCAST_RX_MIC_KEY 8

struct iwl_fmac_sta_key {
	struct rcu_head rcu_head;
	u32 cipher;
	u8 keyidx;
	u8 hw_keyidx;
	u8 iv_len;
	atomic64_t tx_pn;
#ifdef CPTCFG_IWLFMAC_9000_SUPPORT
	u8 tkip_mcast_rx_mic_key[IWL_TKIP_MCAST_RX_MIC_KEY];
#endif /* CPTCFG_IWLFMAC_9000_SUPPORT */
	union {
		u8 pn[IWL_MAX_TID_COUNT][IEEE80211_CCMP_PN_LEN];
		struct iwl_fmac_tkip_tsc tsc[IWL_MAX_TID_COUNT];
	} ____cacheline_aligned_in_smp q[];
};

struct iwl_fmac_tx_stats {
	/* RATE_MCS_* */
	int last_rate;
	u64 bytes;
	u64 packets;
	u32 retries;
	u32 failed;
};

struct iwl_fmac_rx_stats {
	int last_rate; /* RATE_MCS_* */
	unsigned long last_rx;
	int signal;
	u32 packets;
};

struct iwl_fmac_sta_info {
	struct iwl_fmac_tx_stats tx_stats;
	struct iwl_fmac_rx_stats __percpu *pcpu_rx_stats;
	u32 connect_time;
};

/**
 * struct iwl_fmac_amsdu_data - amsdu building data
 * @deadline: when to send this frame
 * @skb: pointer to amsdu skb
 * @amsdu_subframes: # of subframes currently present
 * @amsdu_tbs: # of TBs already going to get used
 */

struct iwl_fmac_amsdu_data {
	u64 deadline;
	struct sk_buff *skb;
	bool csum;
	unsigned int amsdu_subframes;
	unsigned int amsdu_tbs;
};

#define IWL_FMAC_INVALID_STA_ID	0xff
#define IWL_FMAC_MAX_STA 16
#define IWL_MAX_BAID	32
#define IWL_FMAC_NON_QOS_TID IWL_MAX_TID_COUNT
struct iwl_fmac_sta {
	u8 addr[ETH_ALEN];
	u8 sta_id;
	u8 ptk_idx; /* default ptk index */
	u8 gtk_idx; /* default gtk index */
	u16 amsdu_enabled;
	u16 amsdu_size;
	bool qos;
	bool encryption;
	bool authorized;
	bool associated;
	bool he;
	enum nl80211_band band;
	struct iwl_fmac_vif *vif;
	struct iwl_fmac_rxq_dup_data *dup_data;
	struct iwl_fmac_sta_key __rcu *ptk[UMAC_DEFAULT_KEYS];
	struct iwl_fmac_sta_key __rcu *gtk[UMAC_DEFAULT_KEYS];
	struct iwl_fmac_tid tids[IWL_MAX_TID_COUNT];
	struct iwl_fmac_sta_info info;

	/* indication bitmap of deferred traffic per-TID */
	u16 deferred_traffic_tid_map;

	spinlock_t lock; /* To protect operations on the STA */
#ifdef CPTCFG_CFG80211_DEBUGFS
	struct dentry *dbgfs_dir;
#endif

	spinlock_t amsdu_lock;
	struct iwl_fmac_amsdu_data amsdu[IWL_MAX_TID_COUNT];
};

#define for_each_valid_sta(_fmac, _sta, _tmp)				\
	for (_tmp = 0; _tmp < ARRAY_SIZE((_fmac)->stas); _tmp++)	\
		if (((_sta) = rcu_dereference_check((_fmac)->stas[_tmp],\
				    lockdep_is_held(&(_fmac)->mutex))))

enum iwl_fmac_status {
	IWL_STATUS_DUMPING_FW_LOG,
	IWL_STATUS_HW_RFKILL,
	IWL_STATUS_HW_CTKILL,
};

struct iwl_fmac_qos_map {
	struct cfg80211_qos_map qos_map;
	struct rcu_head rcu_head;
};

#ifdef CONFIG_THERMAL
/**
 * struct iwl_fmac_cooling_device
 * @cur_state: current state
 * @cdev: struct thermal cooling device
 */
struct iwl_fmac_cooling_device {
	u32 cur_state;
	struct thermal_cooling_device *cdev;
};

/**
 * struct iwl_fmac_thermal_device - thermal zone related data
 * @temp_trips: temperature thresholds for report
 * @fw_trips_index: keep indexes to original array - temp_trips
 * @tzone: thermal zone device data
 * @notify_thermal_wk: worker to notify thermal manager about
 *	the threshold crossed
 * @ths_crossed: index of threshold crossed
*/
struct iwl_fmac_thermal_device {
	s16 temp_trips[IWL_MAX_DTS_TRIPS];
	u8 fw_trips_index[IWL_MAX_DTS_TRIPS];
	struct thermal_zone_device *tzone;
	struct work_struct notify_thermal_wk;
	u32 ths_crossed;
};

#endif

/**
 * struct iwl_fmac_connect_params - parameters for connect command
 * @max_retries: number of APs to try before notifying a connection failure.
 * @is_passlist: if set, the @bssids array is a passlist (i.e. only the
 *	specified BSSs are allowed for connection). Otherwise it is a blocklist
 *	(i.e. BSSs specified in the list are not allowed for connection).
 * @n_bssids: number of BSSIDs in the @bssids array.
 * @bssids: BSSIDs to passlist/blocklist (see @is_passlist).
 */
struct iwl_fmac_connect_params {
	u8 max_retries;
	bool is_passlist;
	u8 n_bssids;
	u8 bssids[IWL_FMAC_MAX_BSSIDS * ETH_ALEN];
};

struct iwl_fmac {
	/* for logger access */
	struct device *dev;

	struct iwl_trans *trans;
	const struct iwl_fw *fw;
	const struct iwl_cfg *cfg;
	struct iwl_phy_db *phy_db;

	/* for protecting access to iwl_fmac */
	struct mutex mutex;

	/* reference counting of netdev queues stop requests */
	atomic_t netdev_q_stop[AC_NUM];

	atomic_t open_count;

	int sta_generation;

	spinlock_t async_handlers_lock; /* protects handlers list */
	struct list_head async_handlers_list;
	struct work_struct async_handlers_wk;

	struct iwl_notif_wait_data notif_wait;

	/* scan */
	struct cfg80211_scan_request *scan_request;

	/* NVM */
	const char *nvm_file_name;
	struct iwl_nvm_data *nvm_data;
	/* EEPROM MAC addresses */
#define IWL_MAX_ADDRESSES		5
	struct mac_address addresses[IWL_MAX_ADDRESSES];

	/* NVM sections */
	struct iwl_nvm_section nvm_sections[NVM_MAX_NUM_SECTIONS];

	struct iwl_fw_runtime fwrt;

	/* Power */
	int user_power_level; /* in dBm, for all interfaces */

	struct work_struct restart_wk;
	unsigned long status;

	bool shutdown;
	bool rfkill_safe_init_done;

	struct iwl_fmac_reorder_buffer *reorder_bufs[IWL_MAX_BAID];

	struct iwl_fmac_sta __rcu *stas[IWL_FMAC_MAX_STA];
	u8 queue_sta_map[IWL_MAX_TVQM_QUEUES];

	/* data path */
	unsigned long sta_deferred_frames[BITS_TO_LONGS(IWL_FMAC_MAX_STA)];
	struct work_struct add_stream_wk; /* To add streams to queues */
	/* configured by cfg80211 */
	u32 rts_threshold;

	/* regulatory */
	enum iwl_fmac_mcc_source mcc_src;

	/* CT-kill */
	struct delayed_work ct_kill_exit;
#ifdef CONFIG_THERMAL
	struct iwl_fmac_cooling_device cooling_dev;
	struct iwl_fmac_thermal_device tz_device;
#endif

#ifdef CPTCFG_CFG80211_DEBUGFS
	struct dentry *dbgfs_dir;
	struct dentry *dbgfs_dir_stations;
	u8 fw_debug_level;
#endif
#if defined(CPTCFG_CFG80211_DEBUGFS) || \
    defined(CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES)
	bool internal_cmd_to_host;
#endif

	u64 msrment_cookie_counter;

	struct iwl_fmac_connect_params connect_params;
};

static inline struct iwl_fmac *iwl_fmac_from_opmode(struct iwl_op_mode *opmode)
{
	return (void *)opmode->op_mode_specific;
}

static inline struct iwl_fmac *iwl_fmac_from_wiphy(struct wiphy *wiphy)
{
	return iwl_fmac_from_opmode((void *)wiphy->priv);
}

static inline struct wiphy *wiphy_from_fmac(struct iwl_fmac *fmac)
{
	struct iwl_op_mode *opmode = container_of((void *)fmac,
						  struct iwl_op_mode,
						  op_mode_specific);

	return priv_to_wiphy(opmode);
}

enum iwl_fmac_connect_state {
	IWL_FMAC_CONNECT_IDLE,
	IWL_FMAC_CONNECT_CONNECTING,
	IWL_FMAC_CONNECT_CONNECTED,
};

struct iwl_fmac_vif_mgd {
	struct iwl_fmac_sta __rcu *ap_sta;
	u8 wmm_acm;
	enum iwl_fmac_connect_state connect_state;
};

#define MCAST_STA_ADDR (const u8 *)"\x03\x00\x00\x00\x00\x00"

struct iwl_fmac_vif {
	u8 addr[ETH_ALEN];
	u8 id;
	struct iwl_fmac_qos_map __rcu *qos_map;
	struct wireless_dev wdev;
	struct iwl_fmac *fmac;

	struct sk_buff_head pending_skbs[AC_NUM];
	struct hrtimer amsdu_timer;
	u64 cookie;

	union {
		struct iwl_fmac_vif_mgd mgd;
	} u;

	int user_power_level; /* in dBm */
	__be16 control_port_ethertype;

	struct ieee80211_channel *chan;
};

#define FMAC_VIF_ID_INVALID U8_MAX

static inline struct iwl_fmac_vif *vif_from_netdev(struct net_device *dev)
{
	return netdev_priv(dev);
}

static inline struct iwl_fmac_vif *vif_from_wdev(struct wireless_dev *wdev)
{
	return container_of(wdev, struct iwl_fmac_vif, wdev);
}

int iwl_fmac_nl_to_fmac_type(enum nl80211_iftype iftype);

static inline struct iwl_fmac_sta *iwl_get_sta(struct iwl_fmac *fmac,
					       const u8 *addr)
{
	struct iwl_fmac_sta *sta;
	int tmp;

	for_each_valid_sta(fmac, sta, tmp) {
		if (ether_addr_equal(sta->addr, addr))
			return sta;
	}

	return NULL;
}

static inline bool iwl_fmac_is_radio_killed(struct iwl_fmac *fmac)
{
	return test_bit(IWL_STATUS_HW_RFKILL, &fmac->status) ||
	       test_bit(IWL_STATUS_HW_CTKILL, &fmac->status);
}

static inline bool iwl_fmac_firmware_running(struct iwl_fmac *fmac)
{
	lockdep_assert_held(&fmac->mutex);
	return iwl_trans_fw_running(fmac->trans);
}

extern const struct cfg80211_ops iwl_fmac_cfg_ops;

/**
 * struct iwl_fmac_mod_params - module parameters for iwlfmac
 */
struct iwl_fmac_mod_params {
	/**
	 * @power_scheme: see &enum fmac_ps_mode
	 */
	int power_scheme;
	/**
	 * @init_dbg: true to keep the device awake after
	 *	an ASSERT in INIT image
	 */
	bool init_dbg;
	/**
	 * @amsdu_delay: Force A-MSDU building by delaying packets by this many
	 *	milliseconds. Defaults to 0 to not introduce latency at all.
	 */
	unsigned int amsdu_delay;
};

extern struct iwl_fmac_mod_params iwlfmac_mod_params;

void iwl_fmac_setup_wiphy(struct iwl_fmac *fmac);

netdev_tx_t iwl_fmac_dev_start_xmit(struct sk_buff *skb,
				    struct net_device *dev);
enum hrtimer_restart iwl_fmac_amsdu_xmit_timer(struct hrtimer *timer);
void iwl_fmac_tx_send_frame(struct iwl_fmac *fmac,
			    struct iwl_fmac_send_frame_notif *send_frame);

void iwl_fmac_rx_tx_cmd(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb);
void iwl_fmac_rx_ba_notif(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb);
void iwl_fmac_mfu_assert_dump_notif(struct iwl_fmac *fmac,
				    struct iwl_rx_cmd_buffer *rxb);
void iwl_fmac_rx_mpdu(struct iwl_fmac *fmac, struct napi_struct *napi,
		      struct iwl_rx_cmd_buffer *rxb, int queue);
void iwl_fmac_rx_frame_release(struct iwl_fmac *fmac, struct napi_struct *napi,
			       struct iwl_rx_packet *pkt, int queue);
void iwl_fmac_rx_delba_ntfy(struct iwl_fmac *fmac, struct iwl_rx_packet *pkt,
			    int queue);
void iwl_fmac_destroy_reorder_buffer(struct iwl_fmac *fmac,
				     struct iwl_fmac_sta *sta,
				     struct iwl_fmac_reorder_buffer *buf);

void iwl_fmac_add_new_stream_wk(struct work_struct *wk);

enum iwl_fmac_info_flags {
	IWL_FMAC_SKB_INFO_FLAG_BAND_5	= BIT(0),
	IWL_FMAC_SKB_INFO_FLAG_NO_CCK	= BIT(1),
};

/**
 * struct iwl_fmac_tx_data - data for all parts of the TX path
 * @sta: pointer to the station
 * @key: pointer to the key
 * @vif: pointer to the vif
 * @flags: see &enum iwl_fmac_skb_info_flags
 */
struct iwl_fmac_tx_data {
	struct iwl_fmac_sta *sta;
	struct iwl_fmac_vif *vif;
	struct iwl_fmac_sta_key *key;
	u8 flags;
};

/**
 * struct iwl_fmac_skb_info - driver data per skb
 * @dev_cmd: a pointer to the iwl_dev_cmd associated with this skb
 * @cookie: a counter to track the frames coming from hostapd
 * @trans: transport data
 * @amsdu: this packet is an A-MSDU
 */
struct iwl_fmac_skb_info {
	struct {
		struct iwl_device_tx_cmd *dev_cmd;
		u64 cookie;
		void *trans[2];
	};

	u8 amsdu;
};

void iwl_fmac_tx_set_key(struct sk_buff *skb, struct iwl_fmac_tx_data *tx);
int iwl_fmac_tx_skb(struct iwl_fmac *fmac, struct sk_buff *skb,
		    struct iwl_fmac_tx_data *tx);

struct net_device *iwl_fmac_create_netdev(struct iwl_fmac *fmac,
					  const char *name,
					  unsigned char name_assign_type,
					  enum nl80211_iftype iftype,
					  struct vif_params *params);
void iwl_fmac_destroy_vif(struct iwl_fmac_vif *vif);
void iwl_fmac_nic_restart(struct iwl_fmac *fmac);

/* firmware functions */
int iwl_fmac_run_init_fw(struct iwl_fmac *fmac);
int iwl_fmac_run_rt_fw(struct iwl_fmac *fmac);
void iwl_fmac_stop_device(struct iwl_fmac *fmac);
int iwl_fmac_send_cmd(struct iwl_fmac *fmac, struct iwl_host_cmd *cmd);
int iwl_fmac_send_cmd_pdu(struct iwl_fmac *fmac, u32 id,
			  u32 flags, u16 len, const void *data);
int iwl_fmac_send_cmd_status(struct iwl_fmac *fmac, struct iwl_host_cmd *cmd,
			     u32 *status);
int iwl_fmac_send_cmd_pdu_status(struct iwl_fmac *fmac, u32 id, u16 len,
				 const void *data, u32 *status);
void iwl_fmac_dump_nic_error_log(struct iwl_fmac *fmac);
struct ieee80211_regdomain *
iwl_fmac_set_regdom(struct iwl_fmac *fmac, const char *mcc,
		    enum iwl_fmac_mcc_source src_id);

int iwl_fmac_send_config_cmd(struct iwl_fmac *fmac,
			     u8 vif_id, enum iwl_fmac_config_id config_id,
			     const void *data, u16 len);

static inline int
iwl_fmac_send_config_u32(struct iwl_fmac *fmac,
			 u8 vif_id, enum iwl_fmac_config_id config_id,
			 u32 value)
{
	__le32 _value = cpu_to_le32(value);

	return iwl_fmac_send_config_cmd(fmac, vif_id, config_id,
					&_value, sizeof(u32));
}

static inline bool iwl_fmac_has_new_tx_api(struct iwl_fmac *fmac)
{
	/* TODO - replace with TLV once defined */
	return fmac->trans->trans_cfg->use_tfh;
}

static inline bool iwl_fmac_has_unified_ucode(struct iwl_fmac *fmac)
{
	return fmac->trans->trans_cfg->device_family >= IWL_DEVICE_FAMILY_22000;
}

/* vendor cmd */
void iwl_fmac_set_wiphy_vendor_commands(struct wiphy *wiphy);
u32 iwl_fmac_get_phy_config(struct iwl_fmac *fmac);
u8 iwl_fmac_get_valid_tx_ant(struct iwl_fmac *fmac);
u16 iwl_fmac_parse_rates(struct wiphy *wiphy, struct iwl_fmac_vif *vif,
			 const u8 *rates, u8 rates_len);

/* NVM */
int iwl_fmac_nvm_init(struct iwl_fmac *fmac, bool read_nvm_from_nic);
int iwl_fmac_load_nvm_to_nic(struct iwl_fmac *fmac);
int iwl_fmac_send_nvm_cmd(struct iwl_fmac *fmac);

/* STA */
int iwl_fmac_alloc_sta(struct iwl_fmac *fmac, struct iwl_fmac_vif *vif,
		       u8 sta_id, const u8 *addr);
void iwl_fmac_free_sta(struct iwl_fmac *fmac, u8 sta_id, bool hw_error);
void iwl_fmac_destroy_sta_tids(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			       bool hw_error);
void iwl_fmac_flush_sta_queues(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta);
void iwl_fmac_sta_add_key(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			  bool pairwise, const struct iwl_fmac_key *fw_key);
int iwl_fmac_sta_rm_key(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			bool pairwise, u8 keyidx);
void iwl_fmac_destroy_sta_keys(struct iwl_fmac *fmac,
			       struct iwl_fmac_sta *sta);
int iwl_fmac_add_mcast_sta(struct iwl_fmac *fmac,
			   struct iwl_fmac_vif *vif,
			   struct iwl_fmac_sta *sta,
			   u8 sta_id,
			   struct iwl_fmac_keys *keys,
			   u8 mq_id, bool bcast);
void iwl_fmac_remove_mcast_sta(struct iwl_fmac *fmac,
			       struct iwl_fmac_sta *mc_sta);

/* TXQ */
struct iwl_fmac_txq_scd_cfg {
	u8 vif_id;
	u8 fifo;
	u8 sta_id;
	u8 tid;
	bool aggregate;
	int frame_limit;
};

void iwl_fmac_release_txq(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			  int queue, u8 tid);
int iwl_fmac_alloc_queue(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			 u8 tid, struct ieee80211_hdr *hdr);
void iwl_fmac_stop_ac_queue(struct iwl_fmac *fmac, struct wireless_dev *wdev,
			    int ac);
void iwl_fmac_wake_ac_queue(struct iwl_fmac *fmac, struct wireless_dev *wdev,
			    int ac);

/* scan */
int iwl_fmac_abort_scan(struct iwl_fmac *fmac, struct iwl_fmac_vif *vif);

/* thermal */
void iwl_fmac_thermal_initialize(struct iwl_fmac *fmac);
void iwl_fmac_thermal_exit(struct iwl_fmac *fmac);
void iwl_fmac_ct_kill_notif(struct iwl_fmac *fmac,
			    struct iwl_rx_cmd_buffer *rxb);
void iwl_fmac_enter_ctkill(struct iwl_fmac *fmac);
int iwl_fmac_ctdp_command(struct iwl_fmac *fmac, u32 op, u32 state);
int iwl_fmac_get_temp(struct iwl_fmac *fmac, s32 *temp);
#ifdef CONFIG_THERMAL
void iwl_fmac_temp_notif(struct iwl_fmac *fmac,
			 struct iwl_rx_cmd_buffer *rxb);
#endif

/* debugfs */
#ifdef CPTCFG_CFG80211_DEBUGFS
void iwl_fmac_dbgfs_init(struct iwl_fmac *fmac, struct dentry *dbgfs_dir);
void iwl_fmac_dbgfs_exit(struct iwl_fmac *fmac);
void iwl_fmac_dbgfs_add_sta(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta);

void iwl_fmac_dbgfs_del_sta(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta);
#else
static inline void iwl_fmac_dbgfs_init(struct iwl_fmac *fmac,
				       struct dentry *dbgfs_dir) {}
static inline void iwl_fmac_dbgfs_exit(struct iwl_fmac *fmac) {}
static inline void iwl_fmac_dbgfs_add_sta(struct iwl_fmac *fmac,
					  struct iwl_fmac_sta *sta) {}

static inline void iwl_fmac_dbgfs_del_sta(struct iwl_fmac *fmac,
					  struct iwl_fmac_sta *sta) {}
#endif

void iwl_fmac_process_async_handlers(struct iwl_fmac *fmac);

u8 cfg_width_to_iwl_width(enum nl80211_chan_width cfg_width);

void iwl_fmac_disconnected(struct iwl_fmac *fmac, struct iwl_fmac_sta *sta,
			   __le16 reason, u8 locally_generated);

void iwl_fmac_reclaim_and_free(struct iwl_fmac *fmac, u8 sta_id, u8 tid,
			       u16 txq_id, u16 ssn, bool ack);
#endif /* __IWL_FMAC_H__ */

/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_mld_ftm_responder_h__
#define __iwl_mld_ftm_responder_h__

/**
 * struct ftm_responder_data - FTM responder data
 *
 * @resp_pasn_list: a list of PASN stations with security configuration for
 *	each station.
 */
struct ftm_responder_data {
	struct list_head resp_pasn_list;
};

int iwl_mld_ftm_start_responder(struct iwl_mld *mld, struct ieee80211_vif *vif,
				struct ieee80211_bss_conf *bss_conf);
int iwl_mld_ftm_responder_add_pasn_sta(struct iwl_mld *mld,
				       struct ieee80211_vif *vif,
				       u8 *addr, u32 cipher, u8 *tk, u32 tk_len,
				       u8 *hltk, u32 hltk_len);
int iwl_mld_ftm_resp_remove_pasn_sta(struct iwl_mld *mld,
				     struct ieee80211_vif *vif, u8 *addr);
void iwl_mld_ftm_responder_clear(struct iwl_mld *mld,
				 struct ieee80211_vif *vif);
void iwl_mld_ftm_responder_init(struct iwl_mld *mld);

#endif /* __iwl_mld_ftm_responder_h__ */

/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#ifndef __iwl_mld_vend_cmd_h__
#define __iwl_mld_vend_cmd_h__

void iwl_mld_vendor_cmds_register(struct iwl_mld *mld);
void iwl_mld_send_link_info_changed(struct iwl_mld *mld,
				    struct ieee80211_vif *vif);

#endif /* __iwl_mld_vend_cmd_h__ */

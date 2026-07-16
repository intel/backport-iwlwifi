/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024 Intel Corporation
 */
#ifndef __iwl_mld_ax_softap_testmode_h__
#define __iwl_mld_ax_softap_testmode_h__

#include <net/mac80211.h>
#include "mld.h"

void
iwl_mld_ax_softap_testmode_sta_add_debugfs(struct ieee80211_hw *hw,
					   struct ieee80211_vif *vif,
					   struct ieee80211_sta *sta,
					   struct dentry *dir);

#endif /* __iwl_mld_ax_softap_testmode_h__ */

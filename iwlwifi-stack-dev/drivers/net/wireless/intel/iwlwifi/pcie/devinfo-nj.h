// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2005-2014, 2018-2025 Intel Corporation
 * Copyright (C) 2013-2015 Intel Mobile Communications GmbH
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 */

#if IS_ENABLED(CPTCFG_IWLMVM)
	IWL_DEV_INFO(iwl_rf_hr, iwl_ax201_name,
		     RF_TYPE(HR2), SUBDEV(0x0A10)),
	IWL_DEV_INFO(iwl_rf_hr, iwl_ax201_name,
		     RF_TYPE(HR2), SUBDEV(0x0310)),
#endif

#if IS_ENABLED(CPTCFG_IWLMLD)
	IWL_DEV_INFO(iwl_rf_fm, iwl_be201_name,
		     RF_TYPE(FM), SUBDEV(0x0A10), INTEGRATED),
	IWL_DEV_INFO(iwl_rf_fm, iwl_be200_name,
		     RF_TYPE(FM), SUBDEV(0x0A10), DISCRETE),
	IWL_DEV_INFO(iwl_rf_fm, iwl_be201_name,
		     RF_TYPE(FM), SUBDEV(0x0310), INTEGRATED),
	IWL_DEV_INFO(iwl_rf_fm, iwl_be200_name,
		     RF_TYPE(FM), SUBDEV(0x0310), DISCRETE),

	IWL_DEV_INFO(iwl_rf_wh, iwl_be211_name,
		     RF_TYPE(WH), SUBDEV(0x0A10)),
	IWL_DEV_INFO(iwl_rf_wh, iwl_be211_name,
		     RF_TYPE(WH), SUBDEV(0x0310)),
#endif

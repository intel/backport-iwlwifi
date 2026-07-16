// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2005-2014, 2018-2025 Intel Corporation
 * Copyright (C) 2013-2015 Intel Mobile Communications GmbH
 * Copyright (C) 2016-2017 Intel Deutschland GmbH
 */
#ifdef CPTCFG_IWLWIFI_NJ_SUPPORT
#if IS_ENABLED(CPTCFG_IWLMVM)
	{IWL_PCI_DEVICE(0x2720, PCI_ANY_ID, iwl_qnj_mac_cfg)},

	{IWL_PCI_DEVICE(0x2725, 0x0000, iwl_snj_mac_cfg)},
	{IWL_PCI_DEVICE(0x2726, PCI_ANY_ID, iwl_snj_mac_cfg)},
#endif

#if IS_ENABLED(CPTCFG_IWLMLD)
	{IWL_PCI_DEVICE(0x2727, PCI_ANY_ID, iwl_gl_mac_cfg)},
	{IWL_PCI_DEVICE(0x272D, PCI_ANY_ID, iwl_gl_mac_cfg)},

	{IWL_PCI_DEVICE(0x272F, PCI_ANY_ID, iwl_dnj_mac_cfg)},
	{IWL_PCI_DEVICE(0x2730, PCI_ANY_ID, iwl_dnj_mac_cfg)},
#endif
#endif

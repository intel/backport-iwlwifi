// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

const struct iwl_mac_cfg iwl_dnj_mac_cfg = {
	.device_family = IWL_DEVICE_FAMILY_DR,
	.base = &iwl_dr_base,
	.mq_rx_supported = true,
	.gen2 = true,
	.umac_prph_offset = 0x300000,
	.xtal_latency = 12000,
	.low_latency_xtal = true,
};

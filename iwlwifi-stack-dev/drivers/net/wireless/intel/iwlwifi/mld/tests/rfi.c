// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for RFI functions
 *
 * Copyright (C) 2025 Intel Corporation
 */
#include <kunit/static_stub.h>
#include <kunit/test.h>
#include <net/mac80211.h>
#include "mld.h"
#include "rfi.h"
#include "fw/api/rfi.h"
#include "fw/file.h"
#include "utils.h"

#if LINUX_VERSION_IS_LESS(6,13,0)
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
#else
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
#endif

static const struct valid_rfi_link_pair_case {
	const char *desc;
	u8 channel_a;
	u8 channel_b;
	u8 band_a;
	u8 band_b;
	struct iwl_rfi_freq_table_resp_cmd fw_table;
	bool rfi_ddr_valid;
	bool rfi_dlvr_valid;
} valid_rfi_link_pair_cases[] = {
	{
		.desc = "Empty tables",
		.channel_a = 1,
		.channel_b = 2,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.fw_table = {
			.ddr_table = {
				{
					.freq = 0,
					.channels = {},
					.bands = {},
				},
			},
			.dlvr_table = {
				{
					.freq = 0,
					.channels = {},
					.bands = {},
				},
			},
		},
		.rfi_ddr_valid = true,
		.rfi_dlvr_valid = true,
	},
	{
		.desc = "One link has interference with one of DDR and DLVR frequency",
		.channel_a = 5,
		.channel_b = 9,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.fw_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {11, 15, 31},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {11, 15, 31},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = true,
		.rfi_dlvr_valid = true,
	},
	{
		.desc = "Two links has interference with two different DDR and DLVR frequencies",
		.channel_a = 5,
		.channel_b = 9,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.fw_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = false,
		.rfi_dlvr_valid = false,
	},
	{
		.desc = "One frequency that doesn't interfere the link",
		.channel_a = 5,
		.channel_b = 9,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.fw_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(192),
					.channels = {31, 33, 35},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {3, 5, 7},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {9, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1348),
					.channels = {31, 33, 35},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = false,
		.rfi_dlvr_valid = true,
	},
	{
		.desc = "One link has interference with DDR and DLVR frequency",
		.channel_a = 3,
		.channel_b = 7,
		.band_a = PHY_BAND_6,
		.band_b = PHY_BAND_6,
		.fw_table = {
			.ddr_table = {
				{
					.freq = cpu_to_le16(180),
					.channels = {5, 7, 9},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(184),
					.channels = {7, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
			.dlvr_table = {
				{
					.freq = cpu_to_le16(1270),
					.channels = {5, 7, 9},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
				{
					.freq = cpu_to_le16(1290),
					.channels = {7, 11, 15},
					.bands = {PHY_BAND_6, PHY_BAND_6,
						  PHY_BAND_6},
				},
			},
		},
		.rfi_ddr_valid = true,
		.rfi_dlvr_valid = true,
	},
};

KUNIT_ARRAY_PARAM_DESC(valid_rfi_link_pair, valid_rfi_link_pair_cases, desc)

static bool fake_iwl_mld_rfi_supported(struct iwl_mld *mld,
				       enum iwl_mld_rfi_feature rfi_feature)
{
	return true;
}

static void test_rfi_valid_link_pair(struct kunit *test)
{
	const struct valid_rfi_link_pair_case *params = test->param_value;
	struct iwl_mld *mld = test->priv;
	bool dlvr_result;
	bool ddr_result;

	KUNIT_ALLOC_AND_ASSERT(test, mld->rfi.fw_table);
	memcpy(mld->rfi.fw_table, &params->fw_table,
	       sizeof(*mld->rfi.fw_table));

	wiphy_lock(mld->wiphy);
	kunit_activate_static_stub(test, iwl_mld_rfi_supported,
				   fake_iwl_mld_rfi_supported);

	ddr_result = iwl_mld_rfi_ddr_emlsr_accept_link_pair(mld,
							    params->channel_a,
							    params->band_a,
							    params->channel_b,
							    params->band_b);
	dlvr_result = iwl_mld_rfi_dlvr_emlsr_accept_link_pair(mld,
							      params->channel_a,
							      params->band_a,
							      params->channel_b,
							      params->band_b);

	wiphy_unlock(mld->wiphy);
	KUNIT_EXPECT_EQ(test, ddr_result, params->rfi_ddr_valid);
	KUNIT_EXPECT_EQ(test, dlvr_result, params->rfi_dlvr_valid);
}

static struct kunit_case valid_rfi_link_pair_test_cases[] = {
	KUNIT_CASE_PARAM(test_rfi_valid_link_pair,
			 valid_rfi_link_pair_gen_params),
	{},
};

static struct kunit_suite valid_rfi_link_pair = {
	.name = "iwlmld-valid-rfi-link-pair",
	.test_cases = valid_rfi_link_pair_test_cases,
	.init = iwlmld_kunit_test_init,
};

kunit_test_suite(valid_rfi_link_pair);

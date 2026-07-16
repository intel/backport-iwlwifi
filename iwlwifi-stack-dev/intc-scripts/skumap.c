// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * KUnit tests for the iwlwifi devices vs. skumap
 *
 * Copyright (C) 2025 Intel Corporation
 */
#include <kunit/test.h>
#include <linux/pci.h>
#include "iwl-drv.h"
#include "iwl-config.h"

#if LINUX_VERSION_IS_LESS(6,13,0)
MODULE_IMPORT_NS(EXPORTED_FOR_KUNIT_TESTING);
#else
MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
#endif


static const struct dev_entry {
	const char *desc;
	u16 dev_vnd, dev_id, sub_vnd, sub_id;
	u16 phy_id, mac_id;
	u8 phy_step, phy_dash, chains, mac_step;
	enum {
		SKU_TYPE_CRF,
		SKU_TYPE_Discrete,
	} skutype;
	bool phy_jacket;
	bool cdb;
	enum {
		REG_BGN,
		REG_AGN,
		REG_AC,
		REG_AX,
		REG_AX_6G,
		REG_BE,
		REG_BN,
	} reg;
	enum {
		SPECIAL_REG_NONE,
		SPECIAL_REG_No_Limit = SPECIAL_REG_NONE,
		SPECIAL_REG_FCC,
		SPECIAL_REG_Indonesia,
		SPECIAL_REG_Indoor,
		SPECIAL_REG_No_160,
		SPECIAL_REG_No_320,
	} special_reg;
	const char *name;
} skumap_table[] = {
#define DEVICE(_dev_vnd, _dev_id, _sub_vnd, _sub_id, _tp, _phy_id, _phy_step,	\
	       _phy_flavor, _phy_dash, _phy_jacket, _phy_cdb, _chains, _mac_id,	\
	       _mac_step, _regulatory, _special_reg, _jira, _name)		\
	{									\
		.dev_vnd = _dev_vnd,						\
		.dev_id = _dev_id,						\
		.sub_vnd = _sub_vnd,						\
		.sub_id = _sub_id,						\
		.skutype = SKU_TYPE_ ## _tp,					\
		.phy_id = _phy_id,						\
		.phy_step = _phy_step,						\
		.phy_dash = _phy_dash,						\
		.phy_jacket = _phy_jacket,					\
		.cdb = _phy_cdb,						\
		.mac_id = _mac_id,						\
		.mac_step = _mac_step,						\
		.chains = _chains,						\
		.reg = REG_ ## _regulatory,					\
		.special_reg = SPECIAL_REG_ ## _special_reg,			\
		.name = _name,							\
		.desc = "[" _jira "] " _name,					\
	}
#include "skumap.h"
#undef DEVICE
};

KUNIT_ARRAY_PARAM_DESC(skumap_check, skumap_table, desc);

static void skumap_check(struct kunit *test)
{
	const struct dev_entry *entry = (const void *)(test->param_value);
	struct iwl_mac_cfg *mac_cfg = NULL;
	const struct iwl_dev_info *di;
	u32 bandwidth;
	char bwstr[7];

	for (int j = 0; iwl_hw_card_ids[j].vendor; j++) {
		if (iwl_hw_card_ids[j].vendor == entry->dev_vnd &&
		    iwl_hw_card_ids[j].device == entry->dev_id &&
		    (iwl_hw_card_ids[j].subvendor == PCI_ANY_ID ||
		     iwl_hw_card_ids[j].subvendor == entry->sub_vnd) &&
		    (iwl_hw_card_ids[j].subdevice == PCI_ANY_ID ||
		     iwl_hw_card_ids[j].subdevice == entry->sub_id))
			mac_cfg = (void *)iwl_hw_card_ids[j].driver_data;
	}

	KUNIT_ASSERT_NOT_NULL_MSG(test, mac_cfg,
				  "PCI 0x%04x:0x%04x:0x%04x:0x%04x transport cfg not found\n\n",
				  entry->dev_vnd, entry->dev_id,
				  entry->sub_vnd, entry->sub_id);

	KUNIT_EXPECT_EQ_MSG(test,
			    (int)mac_cfg->integrated,
			    entry->skutype == SKU_TYPE_CRF && !entry->phy_jacket,
			    "integrated mismatch (PCI 0x%04x:0x%04x:0x%04x:0x%04x)\n\n",
			    entry->dev_vnd, entry->dev_id,
			    entry->sub_vnd, entry->sub_id);

	/*
	 * Since 9000 series discrete devices are considered Jacket+CRF,
	 * validate the SKUMAP data accordingly.
	 */
	if (entry->skutype == SKU_TYPE_Discrete &&
	    mac_cfg->device_family >= IWL_DEVICE_FAMILY_9000)
		KUNIT_EXPECT_EQ(test, entry->phy_jacket, 1);

	di = iwl_pci_find_dev_info(entry->dev_id, entry->sub_id,
				   entry->phy_id, entry->cdb,
				   /*
				    * The RF ID/BW limit are as in
				    * WREQ-269994, this doesn't do anything
				    * for tests as the SKUMAP doesn't have
				    * the needed data. But we cross-check
				    * the bandwidth below.
				    */
				   IWL_SUBDEVICE_RF_ID(entry->sub_id),
				   IWL_SUBDEVICE_BW_LIM(entry->sub_id),
				   entry->skutype != SKU_TYPE_CRF);
	KUNIT_ASSERT_NOT_NULL_MSG(test, di,
				  "device (RF) info not found\n\n");

	switch (entry->reg) {
	case REG_BGN:
	case REG_AGN:
		bandwidth = 40;
		break;
	case REG_AC:
	case REG_AX:
	case REG_AX_6G:
		bandwidth = 160;
		break;
	case REG_BE:
	case REG_BN:
		bandwidth = 320;
		break;
	}

	switch (entry->special_reg) {
	case SPECIAL_REG_No_160:
		/* validate SKUMAP: no sense limiting to >= capability */
		KUNIT_EXPECT_GT(test, bandwidth, 80);
		/* Check that the BW limit matches between SKUMAP and driver */
		KUNIT_EXPECT_EQ(test, di->cfg->bw_limit, 80);
		bandwidth = 80;
		break;
	case SPECIAL_REG_No_320:
		/* no sense limiting a device that's already that or less */
		KUNIT_EXPECT_GT(test, bandwidth, 160);
		/* Check that the BW limit matches between SKUMAP and driver */
		KUNIT_EXPECT_EQ(test, di->cfg->bw_limit, 160);
		bandwidth = 160;
		break;
	default:
		KUNIT_EXPECT_EQ(test, di->cfg->bw_limit, 0);
		break;
	}

	/* SKUMAP devices should have names */
	KUNIT_ASSERT_NE(test, entry->name[0], 0);

	/* Check that the driver has the right name */
	KUNIT_EXPECT_EQ_MSG(test, strcmp(entry->name, di->name), 0,
			    "name wrong: '%s'\n"
			    "should be:  '%s'\n\n",
			    di->name, entry->name);

	/*
	 * This more of a sanity check for the SKUMAP data itself: if the name
	 * contains a bandwidth (in MHz), then make sure it's actually what we
	 * expect the maximum bandwidth of the device to be based on the other
	 * data we have about it.
	 */
	KUNIT_ASSERT_LT(test,
			snprintf(bwstr, sizeof(bwstr), "%dMHz", bandwidth),
			sizeof(bwstr));
	if (strstr(entry->name, "MHz"))
		KUNIT_EXPECT_NOT_NULL(test, strstr(entry->name, bwstr));
}

static struct kunit_case test_cases[] = {
	KUNIT_CASE_PARAM(skumap_check, skumap_check_gen_params),
	{}
};

static struct kunit_suite iwlwifi_skumap = {
	.name = "iwlwifi-skumap",
	.test_cases = test_cases,
};

kunit_test_suite(iwlwifi_skumap);

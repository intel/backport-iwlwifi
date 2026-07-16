// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#include <linux/etherdevice.h>
#include <net/netlink.h>
#include <net/mac80211.h>
#include "mld.h"
#include "mcc.h"
#include "regulatory.h"
#include "vendor-cmd.h"
#include "iwl-vendor-cmd.h"
#include "fw/api/rfi.h"
#include "rfi.h"
#include "iface.h"
#include "mlo.h"
#include "ftm-initiator.h"
#include "ftm-responder.h"

static int validate_rfi_channel(const struct nlattr *attr,
				struct netlink_ext_ack *extack)
{
	u8 *channel_list = nla_data(attr);

	if (nla_len(attr) !=
	    sizeof(((struct iwl_rfi_ddr_lut_entry *)0)->channels))
		return -EINVAL;

	for (int i = 0; i < nla_len(attr); i++)
		if (channel_list[i] > IWL_RFI_MAX_ALLOWED_CHAN)
			return -EINVAL;

	return 0;
}

static int validate_rfi_bands(const struct nlattr *attr,
			      struct netlink_ext_ack *extack)
{
	u8 *band_list = nla_data(attr);

	if (nla_len(attr) !=
	    sizeof(((struct iwl_rfi_ddr_lut_entry *)0)->bands))
		return -EINVAL;

	for (int i = 0; i < nla_len(attr); i++)
		if (band_list[i] != PHY_BAND_24 &&
		    band_list[i] != PHY_BAND_5 &&
		    band_list[i] != PHY_BAND_6)
			return -EINVAL;

	return 0;
}

static int validate_rfi_desense(const struct nlattr *attr,
				struct netlink_ext_ack *extack)
{
	u8 *desense_list = nla_data(attr);

	if (nla_len(attr) !=
	    sizeof(((struct iwl_rfi_desense_lut_entry *)0)->chain_a))
		return -EINVAL;

	for (int i = 0; i < nla_len(attr); i++)
		if (desense_list[i] > IWL_RFI_MAX_DESENSE)
			return -EINVAL;

	return 0;
}

static const struct nla_policy
iwl_mld_vendor_attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
	[IWL_MVM_VENDOR_ATTR_COUNTRY] = { .type = NLA_STRING, .len = 2 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_RFIM_INFO] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_RFIM_FREQ] = NLA_POLICY_MAX(NLA_U16,
							 IWL_RFI_MAX_FREQ_VAL),
	[IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_channel,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_BANDS] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_bands,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_desense,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE] =
		NLA_POLICY_VALIDATE_FN(NLA_BINARY, validate_rfi_desense,
				       IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM),
	[IWL_MVM_VENDOR_ATTR_RFIM_DDR_SNR_THRESHOLD] =
		NLA_POLICY_MAX(NLA_U32, IWL_RFI_MAX_SNR_THRESHOLD),
	[IWL_MVM_VENDOR_ATTR_RFIM_CNVI_MASTER] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_ADDR] = { .type = NLA_BINARY, .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_STA_CIPHER] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_STA_HLTK] = NLA_POLICY_EXACT_LEN(HLTK_11AZ_LEN),
	[IWL_MVM_VENDOR_ATTR_STA_TK] = { .type = NLA_BINARY,
				         .len = WLAN_KEY_LEN_GCMP_256 },
};

static struct nlattr **iwl_mld_parse_vendor_data(const void *data, int data_len)
{
	struct nlattr **tb;
	int err;

	if (!data)
		return ERR_PTR(-EINVAL);

	tb = kcalloc(MAX_IWL_MVM_VENDOR_ATTR + 1, sizeof(*tb), GFP_KERNEL);
	if (!tb)
		return ERR_PTR(-ENOMEM);

	err = nla_parse(tb, MAX_IWL_MVM_VENDOR_ATTR, data, data_len,
			iwl_mld_vendor_attr_policy, NULL);
	if (err) {
		kfree(tb);
		return ERR_PTR(err);
	}

	return tb;
}

static int iwl_mld_set_country(struct wiphy *wiphy,
			       struct wireless_dev *wdev,
			       const void *data, int data_len)
{
	struct ieee80211_regdomain *regd;
	struct nlattr **tb __free(kfree) = NULL;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	int retval;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_COUNTRY])
		return -EINVAL;

	/* set regdomain information to FW */
	regd = iwl_mld_get_regdomain(mld,
				     nla_data(tb[IWL_MVM_VENDOR_ATTR_COUNTRY]),
				     MCC_SOURCE_MCC_API, NULL);
	if (IS_ERR_OR_NULL(regd))
		return -EIO;

	retval = regulatory_set_wiphy_regd(wiphy, regd);
	kfree(regd);
	return retval;
}

static int iwl_mld_vendor_set_dynamic_txp_profile(struct wiphy *wiphy,
						  struct wireless_dev *wdev,
						  const void *data,
						  int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct nlattr **tb __free(kfree) = NULL;
	u8 chain_a, chain_b;
	int err;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE] ||
	    !tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE])
		return -EINVAL;

	chain_a = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE]);
	chain_b = nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE]);

	if (mld->fwrt.sar_chain_a_profile == chain_a &&
	    mld->fwrt.sar_chain_b_profile == chain_b)
		return 0;

	mld->fwrt.sar_chain_a_profile = chain_a;
	mld->fwrt.sar_chain_b_profile = chain_b;

	/* If the fw is not running, settings will be applied upon fw load */
	if (!mld->fw_status.running)
		return 0;

	err = iwl_mld_config_sar_profile(mld, chain_a, chain_b);

	if (err > 0)
		/* For SAR validation purpose we need to track the exact return
		 * value of iwl_mld_sar_select_profile, mostly to differentiate
		 * between general SAR failure and the case of WRDS disable
		 * (it is illegal if WRDS doesn't exist but WGDS does).
		 * Since nl80211 forbids a positive number as a return value,
		 * in case SAR is disabled overwrite it with -ENOENT.
		 */
		err = -ENOENT;
	return err;
}

static int iwl_mld_vendor_ppag_get_table(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data,
					 int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb = NULL;
	struct nlattr *nl_table;
	int ret, n_subbands, chain;

	/* if ppag is disabled */
	if (!mld->fwrt.ppag_flags)
		return -ENOENT;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 180);
	if (!skb)
		return -ENOMEM;

	nl_table = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_PPAG_TABLE |
				   NLA_F_NESTED);
	if (!nl_table) {
		ret = -ENOBUFS;
		goto err;
	}

	switch (mld->fwrt.ppag_bios_rev) {
	case 0:
		n_subbands = IWL_NUM_SUB_BANDS_V1;
		break;
	case 1 ... 4:
		n_subbands = IWL_NUM_SUB_BANDS_V2;
		break;
	case 5:
		n_subbands = IWL_NUM_SUB_BANDS_V3;
		break;
	default:
		IWL_ERR(mld, "Unknown BIOS revision: %d\n",
			mld->fwrt.ppag_bios_rev);
		ret = -EINVAL;
		goto err;
	}

	for (chain = 0; chain < IWL_NUM_CHAIN_LIMITS; chain++) {
		if (nla_put(skb, chain + 1,
			    n_subbands *
			    sizeof(mld->fwrt.ppag_chains[chain].subbands[0]),
			    &mld->fwrt.ppag_chains[chain].subbands[0])) {
			ret = -ENOBUFS;
			goto err;
		}
	}

	nla_nest_end(skb, nl_table);

	/* put the ppag version */
	if (nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_PPAG_NUM_SUB_BANDS,
			n_subbands)) {
		ret = -ENOBUFS;
		goto err;
	}

	return cfg80211_vendor_cmd_reply(skb);
err:
	kfree_skb(skb);
	return ret;
}

enum iwl_mld_rfi_capabilites {
	IWL_MLD_RFI_DDR_CAPA_CNVI		= BIT(2),
	IWL_MLD_RFI_DDR_CAPA_SCAN		= BIT(3),
	IWL_MLD_RFI_DDR_CAPA_ASSOC		= BIT(4),
	IWL_MLD_RFI_DDR_CAPA_TPT		= BIT(5),
	IWL_MLD_RFI_GET_LINKS_INFO_CAPA		= BIT(7),
	IWL_MLD_RFI_LINK_INFO_CHANGE_CAPA	= BIT(8),
	IWL_MLD_RFI_DLVR_CAPA			= BIT(9),
	IWL_MLD_RFI_DDR_DESENSE_CAPA		= BIT(12),
};

#define IWL_MLD_RFI_DDR_CAPA_ALL (IWL_MLD_RFI_DDR_CAPA_CNVI    |\
				  IWL_MLD_RFI_DDR_CAPA_SCAN     |\
				  IWL_MLD_RFI_DDR_CAPA_ASSOC    |\
				  IWL_MLD_RFI_DDR_CAPA_TPT)

static int iwl_mld_vendor_rfim_get_capa(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	u16 capa = IWL_MLD_RFI_GET_LINKS_INFO_CAPA |
		   IWL_MLD_RFI_LINK_INFO_CHANGE_CAPA;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 4);
	if (!skb)
		return -ENOMEM;

	if (iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DDR_FEATURE))
		capa |= IWL_MLD_RFI_DDR_CAPA_ALL;
	else if (mld->trans->mac_cfg->integrated)
		capa |= IWL_MLD_RFI_DDR_CAPA_CNVI;

	if (iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DLVR_FEATURE))
		capa |= IWL_MLD_RFI_DLVR_CAPA;

	if (iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DESENSE_FEATURE))
		capa |= IWL_MLD_RFI_DDR_DESENSE_CAPA;

	IWL_DEBUG_FW(mld, "RFIm capabilities:%04x\n", capa);
	if (nla_put_u16(skb, IWL_MVM_VENDOR_ATTR_RFIM_CAPA, capa)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return cfg80211_vendor_cmd_reply(skb);
}

#define IWL_RFI_CNVI_NOT_MASTER 0x3

static int iwl_mld_vendor_rfi_set_cnvi_master(struct wiphy *wiphy,
					      struct wireless_dev *wdev,
					      const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	bool old_rfi_wlan_master = mld->rfi.wlan_master;
	struct nlattr **tb __free(kfree) = NULL;
	u32 rfi_master_conf;
	int err = 0;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_RFIM_CNVI_MASTER])
		return -EINVAL;

	rfi_master_conf = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_RFIM_CNVI_MASTER]);
	IWL_DEBUG_INFO(mld, "rfi cnvi master conf is 0x%08x\n",
		       rfi_master_conf);
	rfi_master_conf &= IWL_RFI_CNVI_NOT_MASTER;

	/* rfi_master_conf can be 0 or 3 only.
	 * i.e 0 means CNVI is master. 3 means user-space application is master.
	 * 1 and 2 are invalid configurations, which means there is no way for
	 * the user space to take partial control.
	 */
	if (!rfi_master_conf)
		mld->rfi.wlan_master = true;
	else if (rfi_master_conf == IWL_RFI_CNVI_NOT_MASTER)
		mld->rfi.wlan_master = false;
	else
		return -EINVAL;

	/* ignore if nothing changed */
	if (old_rfi_wlan_master == mld->rfi.wlan_master) {
		IWL_DEBUG_INFO(mld,
			       "Wlan RFI master configuration is same as old:%d\n",
			       old_rfi_wlan_master);
		return 0;
	}

	/* Drop external stored configuration buffer when there is
	 * change in master
	 */
	kfree(mld->rfi.external_config_info);
	mld->rfi.external_config_info = NULL;

	/* By-pass sending of RFI_CONFIG command, if user space takes control
	 * when rfi "rfi_state" is not PMC_SUPPORTED or SUBSET_TABLE_READY.
	 */
	if (mld->rfi.wlan_master ||
	    mld->rfi.fw_state == IWL_RFI_PMC_SUPPORTED ||
	    mld->rfi.fw_state == IWL_RFI_DDR_SUBSET_TABLE_READY)
		err = iwl_mld_rfi_send_config_cmd(mld);

	if (err)
		mld->rfi.wlan_master = old_rfi_wlan_master;

	return err;
}

static bool
iwl_mld_vendor_valid_rfim_info_attr(struct iwl_mld *mld,
				    struct nlattr *rfim_info_attr)
{
	struct iwl_mld_rfi_config_info *rfi_config_info = NULL;
	bool snr_threshold_present = false;
	bool channel_list_present = true;
	bool chain_a_list_present = true;
	bool chain_b_list_present = true;
	bool band_list_present = true;
	bool has_rfi_desense_support;
	struct nlattr *attr;
	int row_idx = -1; /* the row is updated only at frequency attr */
	int rem;

	if (!rfim_info_attr)
		return false;

	has_rfi_desense_support =
		iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DESENSE_FEATURE);

	BUILD_BUG_ON(ARRAY_SIZE(rfi_config_info->ddr_table) !=
		     ARRAY_SIZE(rfi_config_info->desense_table));
	nla_for_each_nested(attr, rfim_info_attr, rem) {
		switch (nla_type(attr)) {
		case IWL_MVM_VENDOR_ATTR_RFIM_FREQ:
			if (!channel_list_present || !band_list_present ||
			    chain_a_list_present != chain_b_list_present)
				return false;

			band_list_present = false;
			channel_list_present = false;
			chain_a_list_present = false;
			chain_b_list_present = false;

			row_idx++;
			if (row_idx >= ARRAY_SIZE(rfi_config_info->ddr_table))
				return false;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS:
			if (row_idx < 0 || channel_list_present)
				return false;

			channel_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_BANDS:
			if (row_idx < 0 || band_list_present)
				return false;

			band_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE:
			if (row_idx < 0 || chain_a_list_present ||
			    !has_rfi_desense_support)
				return false;

			chain_a_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE:
			if (row_idx < 0 || chain_b_list_present ||
			    !has_rfi_desense_support)
				return false;

			chain_b_list_present = true;
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_DDR_SNR_THRESHOLD:
			if (snr_threshold_present)
				return false;

			snr_threshold_present = true;
			break;
		default:
			IWL_ERR(mld, "Invalid attribute %d\n", nla_type(attr));
			return false;
		}
	}

	return row_idx >= 0 && channel_list_present && band_list_present &&
	       chain_a_list_present == chain_b_list_present;
}

static int iwl_mld_vendor_rfi_set_table(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct iwl_mld_rfi_config_info *rfi_config_info __free(kfree) = NULL;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct nlattr **tb __free(kfree) = NULL;
	struct nlattr *attr;
	int rem, err = 0;
	int row_idx = -1; /* the row is updated only at frequency attr */

	if (!iwl_mld_rfi_supported(mld, IWL_MLD_RFI_DDR_FEATURE))
		return -EINVAL;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!iwl_mld_vendor_valid_rfim_info_attr(mld,
						 tb[IWL_MVM_VENDOR_ATTR_RFIM_INFO]))
		return -EINVAL;

	rfi_config_info = kzalloc(sizeof(*rfi_config_info), GFP_KERNEL);
	if (!rfi_config_info)
		return -ENOMEM;

	/* Fill rfi_config_info with default data to have compatibility
	 * with old RFI user application.
	 */
	memset(rfi_config_info->desense_table, IWL_RFI_DDR_DESENSE_VALUE,
	       sizeof(rfi_config_info->desense_table));
	rfi_config_info->snr_threshold = cpu_to_le32(IWL_RFI_DDR_SNR_THRESHOLD);

	nla_for_each_nested(attr, tb[IWL_MVM_VENDOR_ATTR_RFIM_INFO], rem) {
		switch (nla_type(attr)) {
		case IWL_MVM_VENDOR_ATTR_RFIM_FREQ:
			row_idx++;
			rfi_config_info->ddr_table[row_idx].freq =
				cpu_to_le16(nla_get_u16(attr));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS:
			memcpy(rfi_config_info->ddr_table[row_idx].channels,
			       nla_data(attr),
			       sizeof(rfi_config_info->ddr_table[0].channels));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_BANDS:
			memcpy(rfi_config_info->ddr_table[row_idx].bands,
			       nla_data(attr),
			       sizeof(rfi_config_info->ddr_table[0].bands));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE:
			memcpy(rfi_config_info->desense_table[row_idx].chain_a,
			       nla_data(attr),
			       sizeof(rfi_config_info->desense_table[0].chain_a));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE:
			memcpy(rfi_config_info->desense_table[row_idx].chain_b,
			       nla_data(attr),
			       sizeof(rfi_config_info->desense_table[0].chain_b));
			break;
		case IWL_MVM_VENDOR_ATTR_RFIM_DDR_SNR_THRESHOLD:
			rfi_config_info->snr_threshold =
				cpu_to_le32(nla_get_u32(attr));
			break;
		}
	}

	/* Skip sending RFI_CONFIG_CMD to FW when RFI table is same as
	 * previous
	 */
	if (mld->rfi.external_config_info &&
	    !memcmp(rfi_config_info, mld->rfi.external_config_info,
		    sizeof(*rfi_config_info))) {
		IWL_DEBUG_INFO(mld, "Skip sending RFI_CONFIG_CMD\n");
		return 0;
	}

	swap(mld->rfi.external_config_info, rfi_config_info);
	err = iwl_mld_rfi_send_config_cmd(mld);
	if (err) {
		IWL_ERR(mld, "Failed to send rfi table to FW, error %d\n", err);
		kfree(mld->rfi.external_config_info);
		mld->rfi.external_config_info = NULL;
	}

	return err;
}

/* RFIM_INFO requires 4 bytes for nlattr.
 * DDR table will have 4 entries and each entry contains, frequency which
 * requires 2 bytes for it and 4 bytes for nlattr. channel, bands, chain_a and
 * chain_b requires 15 bytes each of it and 4 bytes each nlattr, extra 18 bytes
 * for future. So, response size is 4 + 4 * (2 + 4 + 4 * (15 + 4)) + 18 = 350
 */

#define RFI_GET_TABLE_RESP_SIZE		350
static int iwl_mld_vendor_rfi_get_table(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	const struct iwl_rfi_freq_table_resp_cmd *fw_table;
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb = NULL;
	struct nlattr *rfim_info;
	int ret;

	fw_table = mld->rfi.fw_table;
	if (!fw_table)
		return -EOPNOTSUPP;

	if (fw_table->status != RFI_FREQ_TABLE_OK)
		return -EINVAL;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  RFI_GET_TABLE_RESP_SIZE);
	if (!skb)
		return -ENOMEM;

	rfim_info = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_RFIM_INFO |
					NLA_F_NESTED);
	if (!rfim_info) {
		ret = -ENOBUFS;
		goto err;
	}

	BUILD_BUG_ON(ARRAY_SIZE(fw_table->ddr_table) !=
		     ARRAY_SIZE(fw_table->desense_table));

	for (int i = 0; i < ARRAY_SIZE(fw_table->ddr_table); i++) {
		if (nla_put_u16(skb, IWL_MVM_VENDOR_ATTR_RFIM_FREQ,
				le16_to_cpu(fw_table->ddr_table[i].freq)) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_CHANNELS,
			    sizeof(fw_table->ddr_table[i].channels),
			    fw_table->ddr_table[i].channels) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_BANDS,
			    sizeof(fw_table->ddr_table[i].bands),
			    fw_table->ddr_table[i].bands) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_A_DESENSE,
			    sizeof(fw_table->desense_table[i].chain_a),
			    fw_table->desense_table[i].chain_a) ||
		    nla_put(skb, IWL_MVM_VENDOR_ATTR_RFIM_CHAIN_B_DESENSE,
			    sizeof(fw_table->desense_table[i].chain_b),
			    fw_table->desense_table[i].chain_b)) {
			ret = -ENOBUFS;
			goto err;
		}
	}

	nla_nest_end(skb, rfim_info);

	return cfg80211_vendor_cmd_reply(skb);

err:
	kfree_skb(skb);
	return ret;
}

static int
iwl_mld_vendor_exit_emlsr(struct wiphy *wiphy, struct wireless_dev *wdev,
			  const void *data, int data_len)
{
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	struct iwl_mld *mld;

	if (!vif)
		return -ENODEV;

	mld = iwl_mld_vif_from_mac80211(vif)->mld;

	if (mld->rfi.wlan_master)
		return -EINVAL;

	iwl_mld_exit_emlsr(mld, vif, IWL_MLD_EMLSR_EXIT_RFI,
			   iwl_mld_get_primary_link(vif));
	return 0;
}

static int iwl_mld_vendor_put_geo_profile(struct iwl_mld *mld,
					  struct sk_buff *skb, int profile)
{
	for (int i = 0; i < BIOS_GEO_MAX_NUM_BANDS; i++) {
		struct nlattr *nl_band = nla_nest_start(skb, i + 1);

		if (!nl_band)
			return -ENOBUFS;

		if (nla_put_u8(skb, IWL_VENDOR_SAR_GEO_MAX_TXP,
			       mld->fwrt.geo_profiles[profile - 1].bands[i].max) ||
		    nla_put_u8(skb, IWL_VENDOR_SAR_GEO_CHAIN_A_OFFSET,
			       mld->fwrt.geo_profiles[profile - 1].bands[i].chains[0]) ||
		    nla_put_u8(skb, IWL_VENDOR_SAR_GEO_CHAIN_B_OFFSET,
			       mld->fwrt.geo_profiles[profile - 1].bands[i].chains[1]))
			return -ENOBUFS;
		nla_nest_end(skb, nl_band);
	}
	return 0;
}

static int iwl_mld_vendor_get_geo_profile_info(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data,
					       int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb;
	struct nlattr *nl_profile;
	int tbl_idx, ret;

	tbl_idx = iwl_mld_get_sar_geo_profile(mld);
	if (tbl_idx < 0)
		return tbl_idx;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;

	nl_profile = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_SAR_GEO_PROFILE);
	if (!nl_profile) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	/* If the index is 0, then we can't have any offset */
	if (!tbl_idx)
		goto out;

	/* put into the skb the info for profile tbl_idx */
	ret = iwl_mld_vendor_put_geo_profile(mld, skb, tbl_idx);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}
out:
	nla_nest_end(skb, nl_profile);

	return cfg80211_vendor_cmd_reply(skb);
}

static int iwl_mld_vendor_get_sar_profile_info(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data,
					       int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb;
	u32 n_profiles = 0;

	for (int i = 0; i < ARRAY_SIZE(mld->fwrt.sar_profiles); i++) {
		if (mld->fwrt.sar_profiles[i].enabled)
			n_profiles++;
	}

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;
	if (nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_SAR_ENABLED_PROFILE_NUM,
		       n_profiles) ||
	    nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_A_PROFILE,
		       mld->fwrt.sar_chain_a_profile) ||
	    nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_SAR_CHAIN_B_PROFILE,
		       mld->fwrt.sar_chain_b_profile)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return cfg80211_vendor_cmd_reply(skb);
}

static int iwl_mld_vendor_sar_get_table(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct sk_buff *skb = NULL;
	struct nlattr *nl_table;
	int ret, fw_ver;

	/* if wrds is disabled - ewrd must be disabled too */
	if (!mld->fwrt.sar_profiles[0].enabled)
		return -ENOENT;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 100);
	if (!skb)
		return -ENOMEM;

	nl_table = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_SAR_TABLE);
	if (!nl_table) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	for (int prof = 0; prof < ARRAY_SIZE(mld->fwrt.sar_profiles); prof++) {
		struct nlattr *nl_profile;

		if (!mld->fwrt.sar_profiles[prof].enabled)
			break;

		nl_profile = nla_nest_start(skb, prof + 1);
		if (!nl_profile) {
			ret = -ENOBUFS;
			goto err;
		}

		/* put info per chain */
		for (int chain = 0;
		     chain < ARRAY_SIZE(mld->fwrt.sar_profiles[prof].chains);
		     chain++) {
			if (nla_put(skb, chain + 1,
				    ARRAY_SIZE(mld->fwrt.sar_profiles[prof].chains[chain].subbands),
				    mld->fwrt.sar_profiles[prof].chains[chain].subbands)) {
				ret = -ENOBUFS;
				goto err;
			}
		}

		nla_nest_end(skb, nl_profile);
	}
	nla_nest_end(skb, nl_table);

	fw_ver = iwl_fw_lookup_cmd_ver(mld->fw, REDUCE_TX_POWER_CMD,
				       IWL_FW_CMD_VER_UNKNOWN);

	if (nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_SAR_VER, fw_ver)) {
		ret = -ENOBUFS;
		goto err;
	}
	return cfg80211_vendor_cmd_reply(skb);
err:
	kfree_skb(skb);
	return ret;
}

static int iwl_mld_vendor_add_pasn_sta(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       const void *data, int data_len)
{
	struct nlattr **tb __free(kfree) = NULL;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	u8 *addr, *tk = NULL, *hltk;
	u32 tk_len = 0, hltk_len, cipher;
	int ret = 0;
	struct ieee80211_sta *sta;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_ADDR] ||
	    (!tb[IWL_MVM_VENDOR_ATTR_STA_HLTK] &&
	     !tb[IWL_MVM_VENDOR_ATTR_STA_TK]) ||
	    !tb[IWL_MVM_VENDOR_ATTR_STA_CIPHER])
		return -EINVAL;

	addr = nla_data(tb[IWL_MVM_VENDOR_ATTR_ADDR]);
	cipher = nla_get_u32(tb[IWL_MVM_VENDOR_ATTR_STA_CIPHER]);
	if (tb[IWL_MVM_VENDOR_ATTR_STA_HLTK]) {
		hltk = nla_data(tb[IWL_MVM_VENDOR_ATTR_STA_HLTK]);
		hltk_len = nla_len(tb[IWL_MVM_VENDOR_ATTR_STA_HLTK]);
	} else {
		hltk = NULL;
		hltk_len = 0;
	}

	if (!vif)
		return -ENODEV;

	sta = ieee80211_find_sta(vif, addr);
	if ((!tb[IWL_MVM_VENDOR_ATTR_STA_TK] && (!sta || !sta->mfp)) ||
	    (tb[IWL_MVM_VENDOR_ATTR_STA_TK] && sta && sta->mfp))
		return ret;

	if (tb[IWL_MVM_VENDOR_ATTR_STA_TK]) {
		u32 expected_tk_len = cipher == WLAN_CIPHER_SUITE_GCMP_256 ?
			WLAN_KEY_LEN_GCMP_256 : WLAN_KEY_LEN_CCMP;

		tk = nla_data(tb[IWL_MVM_VENDOR_ATTR_STA_TK]);
		tk_len = nla_len(tb[IWL_MVM_VENDOR_ATTR_STA_TK]);
		if (tk_len != expected_tk_len)
			return -EINVAL;
	}

	if (vif->bss_conf.ftm_responder)
		return iwl_mld_ftm_responder_add_pasn_sta(mld, vif, addr,
							  cipher, tk, tk_len,
							  hltk, hltk_len);
	else
		return iwl_mld_ftm_add_pasn_sta(mld, vif, addr, cipher, tk,
						tk_len, hltk, hltk_len);
}

static int iwl_mld_vendor_remove_pasn_sta(struct wiphy *wiphy,
					  struct wireless_dev *wdev,
					  const void *data, int data_len)
{
	struct nlattr **tb __free(kfree) = NULL;
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	u8 *addr;
	int ret = 0;

	tb = iwl_mld_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_ADDR])
		return -EINVAL;

	addr = nla_data(tb[IWL_MVM_VENDOR_ATTR_ADDR]);

	if (!vif)
		return -ENODEV;

	if (vif->bss_conf.ftm_responder)
		iwl_mld_ftm_resp_remove_pasn_sta(mld, vif, addr);
	else
		iwl_mld_ftm_remove_pasn_sta(mld, addr);
	return ret;
}

static int
iwl_mld_fill_vendor_link_type(struct ieee80211_vif *vif, struct sk_buff *skb,
			      unsigned int link_id)
{
	lockdep_assert_held(&ieee80211_vif_to_wdev(vif)->wiphy->mtx);

	if (ieee80211_vif_type_p2p(vif) == NL80211_IFTYPE_STATION) {
		if (link_id == iwl_mld_get_primary_link(vif))
			return nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_LINK_TYPE,
					  IWL_VENDOR_PRIMARY_LINK);
		return nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_LINK_TYPE,
				  IWL_VENDOR_SECONDARY_LINK);
	}
	return 0;
}

static int
iwl_mld_vendor_cmd_fill_links_info(struct wiphy *wiphy,
				   struct ieee80211_vif *vif,
				   struct sk_buff *skb)
{
	struct ieee80211_bss_conf *link_conf;
	unsigned int link_id;

	lockdep_assert_held(&wiphy->mtx);

	for_each_vif_active_link(vif, link_conf, link_id) {
		const struct cfg80211_chan_def *chandef;
		u8 channel;
		u8 fw_band;

		chandef = &link_conf->chanreq.oper;
		if (!cfg80211_chandef_valid(chandef) || !link_conf->bss)
			continue;

		channel = ieee80211_frequency_to_channel(chandef->center_freq1);
		fw_band = iwl_mld_nl80211_band_to_fw(chandef->chan->band);
		if (nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_CHANNEL, channel) ||
		    nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_PHY_BAND, fw_band) ||
		    nla_put_u8(skb, IWL_MVM_VENDOR_ATTR_RSSI,
			       link_conf->bss->signal) ||
		    nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_WIPHY_FREQ,
				chandef->chan->center_freq) ||
		    nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_CHANNEL_WIDTH,
				chandef->width) ||
		    nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_CENTER_FREQ1,
				chandef->center_freq1) ||
		    (chandef->center_freq2 &&
		     nla_put_u32(skb, IWL_MVM_VENDOR_ATTR_CENTER_FREQ2,
				 chandef->center_freq2)) ||
		    iwl_mld_fill_vendor_link_type(vif, skb, link_id))
			return -ENOBUFS;
	}

	return 0;
}

static int iwl_mld_vendor_get_links_info(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data, int data_len)
{
	struct ieee80211_vif *vif = wdev_to_ieee80211_vif(wdev);
	struct nlattr *link_info_attr;
	struct sk_buff *skb = NULL;
	int ret;

	if (!vif)
		return -ENODEV;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, NLMSG_GOODSIZE);
	if (!skb)
		return -ENOMEM;

	link_info_attr = nla_nest_start(skb, IWL_MVM_VENDOR_ATTR_LINKS_INFO);
	if (!link_info_attr) {
		ret = -ENOBUFS;
		goto err;
	}

	ret = iwl_mld_vendor_cmd_fill_links_info(wiphy, vif, skb);
	if (ret)
		goto err;

	nla_nest_end(skb, link_info_attr);
	return cfg80211_vendor_cmd_reply(skb);

err:
	kfree_skb(skb);
	return ret;
}

static int iwl_mld_vendor_dbg_clear_monitor_buf(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data, int data_len)
{
	struct ieee80211_hw *hw = wiphy_to_ieee80211_hw(wiphy);
	struct iwl_mld *mld = IWL_MAC80211_GET_MLD(hw);

	/* If the firmware is not running, silently succeed since there is
	 * no data to clear.
	 */
	if (!mld->fw_status.running)
		return 0;

	iwl_fw_dbg_clear_monitor_buf(&mld->fwrt);
	return 0;
}

static const struct wiphy_vendor_command iwl_mld_vendor_commands[] = {
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_COUNTRY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_set_country,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_SAR_PROFILE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_set_dynamic_txp_profile,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_GET_SAR_GEO_PROFILE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_get_geo_profile_info,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_GET_SAR_PROFILE_INFO,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_get_sar_profile_info,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_PPAG_GET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_ppag_get_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RFIM_GET_CAPA,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_rfim_get_capa,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RFIM_SET_CNVI_MASTER,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_rfi_set_cnvi_master,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RFIM_SET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_rfi_set_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_RFIM_GET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_rfi_get_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_EXIT_EMLSR,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_exit_emlsr,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SAR_GET_TABLE,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV,
		.doit = iwl_mld_vendor_sar_get_table,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_ADD_PASN_STA,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_add_pasn_sta,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_REMOVE_PASN_STA,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_remove_pasn_sta,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_GET_LINK_INFO,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_get_links_info,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_DBG_CLEAR_MONITOR_BUFFER,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_mld_vendor_dbg_clear_monitor_buf,
		.policy = iwl_mld_vendor_attr_policy,
		.maxattr = MAX_IWL_MVM_VENDOR_ATTR,
	},
};

enum iwl_mvm_vendor_events_idx {
	IWL_MLD_VENDOR_EVENT_IDX_LINK_INFO_CHANGED,
	NUM_IWL_MLD_VENDOR_EVENT_IDX,
};

static const struct nl80211_vendor_cmd_info
iwl_mld_vendor_events[NUM_IWL_MLD_VENDOR_EVENT_IDX] = {
	[IWL_MLD_VENDOR_EVENT_IDX_LINK_INFO_CHANGED] = {
		.vendor_id = INTEL_OUI,
		.subcmd = IWL_MVM_VENDOR_CMD_LINK_INFO_CHANGED_EVENT,
	},
};

void iwl_mld_send_link_info_changed(struct iwl_mld *mld,
				    struct ieee80211_vif *vif)
{
	int event_idx = IWL_MLD_VENDOR_EVENT_IDX_LINK_INFO_CHANGED;
	struct sk_buff *msg;

	msg = cfg80211_vendor_event_alloc(mld->hw->wiphy,
					  ieee80211_vif_to_wdev(vif), 0,
					  event_idx, GFP_ATOMIC);
	if (msg)
		cfg80211_vendor_event(msg, GFP_ATOMIC);
}

void iwl_mld_vendor_cmds_register(struct iwl_mld *mld)
{
	mld->hw->wiphy->vendor_commands = iwl_mld_vendor_commands;
	mld->hw->wiphy->n_vendor_commands = ARRAY_SIZE(iwl_mld_vendor_commands);
	mld->hw->wiphy->vendor_events = iwl_mld_vendor_events;
	mld->hw->wiphy->n_vendor_events = ARRAY_SIZE(iwl_mld_vendor_events);
}

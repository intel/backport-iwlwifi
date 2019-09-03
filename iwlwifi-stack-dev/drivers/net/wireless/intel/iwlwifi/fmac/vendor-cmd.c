/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2012 - 2014 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 - 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#include <linux/etherdevice.h>
#include <net/mac80211.h>
#include <net/netlink.h>
#include "fmac.h"
#include "iwl-vendor-cmd.h"

static const struct nla_policy
iwl_fmac_vendor_attr_policy[NUM_IWL_MVM_VENDOR_ATTR] = {
	[IWL_MVM_VENDOR_ATTR_LOW_LATENCY] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_COUNTRY] = { .type = NLA_STRING, .len = 2 },
	[IWL_MVM_VENDOR_ATTR_FILTER_ARP_NA] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_FILTER_GTK] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_ADDR] = { .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_24] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52L] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_TXP_LIMIT_52H] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_OPPPS_WA] = { .type = NLA_FLAG },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR] = { .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MAC_ADDR_MASK] = { .len = ETH_ALEN },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MAX_AP_PER_SCAN] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_BUCKET_SPECS] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_GSCAN_LOST_AP_SAMPLE_SIZE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_AP_LIST] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_GSCAN_RSSI_SAMPLE_SIZE] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_GSCAN_MIN_BREACHING] = { .type = NLA_U8 },
	[IWL_MVM_VENDOR_ATTR_RXFILTER] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_RXFILTER_OP] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_DBG_COLLECT_TRIGGER] = { .type = NLA_STRING },
	[IWL_MVM_VENDOR_ATTR_GSCAN_REPORT_THRESHOLD_NUM] = { .type = NLA_U32 },
	[IWL_MVM_VENDOR_ATTR_SSID] = { .type = NLA_BINARY,
				       .len = IEEE80211_MAX_SSID_LEN },
	[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF] = { .type = NLA_NESTED },
	[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_MAX_RETRIES] = {
		.type = NLA_U8 },
};

static struct nlattr **
iwl_fmac_parse_vendor_data(const void *data, int data_len)
{
	struct nlattr **tb;
	int err;

	if (!data)
		return ERR_PTR(-EINVAL);

	tb = kcalloc(MAX_IWL_MVM_VENDOR_ATTR + 1, sizeof(*tb), GFP_KERNEL);
	if (!tb)
		return ERR_PTR(-ENOMEM);

	err = nla_parse(tb, MAX_IWL_MVM_VENDOR_ATTR, data, data_len,
			iwl_fmac_vendor_attr_policy, NULL);
	if (err) {
		kfree(tb);
		return ERR_PTR(err);
	}

	return tb;
}

static int iwl_fmac_set_country(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				const void *data, int data_len)
{
	struct ieee80211_regdomain *regd;
	struct nlattr **tb;
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	int err;

	tb = iwl_fmac_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (!tb[IWL_MVM_VENDOR_ATTR_COUNTRY]) {
		err = -EINVAL;
		goto free;
	}

	mutex_lock(&fmac->mutex);

	/* set regdomain information to FW */
	regd = iwl_fmac_set_regdom(fmac,
				   nla_data(tb[IWL_MVM_VENDOR_ATTR_COUNTRY]),
				   IWL_FMAC_MCC_SOURCE_3G_LTE_HOST);
	if (IS_ERR_OR_NULL(regd)) {
		err = -EIO;
		goto unlock;
	}

	err = regulatory_set_wiphy_regd(wiphy, regd);
	kfree(regd);
unlock:
	mutex_unlock(&fmac->mutex);
free:
	kfree(tb);
	return err;
}

static int iwl_fmac_fips_sha_type(u8 vendor_type, u8 *fmac_type)
{
	switch (vendor_type) {
	case IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA1:
		*fmac_type = IWL_FMAC_SHA_TYPE_SHA1;
		return 0;
	case IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA256:
		*fmac_type = IWL_FMAC_SHA_TYPE_SHA256;
		return 0;
	case IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA384:
		*fmac_type = IWL_FMAC_SHA_TYPE_SHA384;
		return 0;
	default:
		return -EINVAL;
	}
}

static int iwl_fmac_hmac_res_len_is_valid(u8 sha_type, u8 res_len)
{
	switch (sha_type) {
	case IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA1:
		return res_len <= MAX_RES_LEN_HMAC_SHA1;
	case IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA256:
		return res_len <= MAX_RES_LEN_HMAC_SHA256;
	case IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA384:
		return res_len <= MAX_RES_LEN_HMAC_SHA384;
	default:
		return 0;
	}
}

static const struct nla_policy
iwl_fmac_vendor_vector_sha_policy[NUM_IWL_VENDOR_FIPS_TEST_VECTOR_SHA] = {
	[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE] = { .type = NLA_U8 },
	[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG] = { .type = NLA_BINARY },
};

static int iwl_fmac_build_sha_cmd(struct iwl_fmac_test_fips_cmd *cmd,
				  struct nlattr *test_vector)
{
	struct iwl_fmac_vector_sha *vector;
	struct nlattr *tb[NUM_IWL_VENDOR_FIPS_TEST_VECTOR_SHA];
	int err;
	u8 type;

	err = nla_parse_nested(tb, MAX_IWL_VENDOR_FIPS_TEST_VECTOR_SHA,
			       test_vector, iwl_fmac_vendor_vector_sha_policy,
			       NULL);
	if (err)
		return err;

	if (!tb[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE] ||
	    !tb[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG])
		return -EINVAL;

	vector = (void *)cmd->vector;

	type = nla_get_u8(tb[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE]);
	err = iwl_fmac_fips_sha_type(type, &vector->type);
	if (err)
		return -EINVAL;

	vector->msg_len = nla_len(tb[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG]);
	if (vector->msg_len > SHA_MAX_MSG_LEN)
		return -EINVAL;

	memcpy(vector->msg, nla_data(tb[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_MSG]),
	       vector->msg_len);
	return 0;
}

static const struct nla_policy
iwl_fmac_vendor_vector_hmac_kdf_policy[NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF] = {
	[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_TYPE] = { .type = NLA_U8 },
	[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_RES_LEN] = { .type = NLA_U8 },
	[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY] = { .type = NLA_BINARY },
	[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG] = { .type = NLA_BINARY },
};

static int iwl_fmac_build_hmac_kdf_cmd(struct iwl_fmac_test_fips_cmd *cmd,
				       struct nlattr *test_vector)
{
	struct iwl_fmac_vector_hmac_kdf *vector;
	struct nlattr *tb[NUM_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF];
	int err;
	u8 type;

	err = nla_parse_nested(tb, MAX_IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF,
			       test_vector,
			       iwl_fmac_vendor_vector_hmac_kdf_policy,
			       NULL);
	if (err)
		return err;

	if (!tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_TYPE] ||
	    !tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY] ||
	    !tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG] ||
	    !tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_RES_LEN])
		return -EINVAL;

	vector = (void *)cmd->vector;

	type = nla_get_u8(tb[IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE]);
	err = iwl_fmac_fips_sha_type(type, &vector->type);
	if (err)
		return -EINVAL;

	/* KDF test is only supported for SHA256 and SHA384 */
	if (cmd->type == IWL_FMAC_FIPS_TEST_KDF &&
	    type == IWL_VENDOR_FIPS_TEST_VECTOR_SHA_TYPE_SHA1)
		return -EINVAL;

	vector->res_len =
		nla_get_u8(tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_RES_LEN]);
	if (vector->res_len > FIPS_MAX_RES_LEN)
		return -EINVAL;

	if (cmd->type == IWL_FMAC_FIPS_TEST_HMAC &&
	    !iwl_fmac_hmac_res_len_is_valid(vector->type, vector->res_len))
		return -EINVAL;

	vector->key_len = nla_len(tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY]);
	vector->msg_len = nla_len(tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG]);
	if (vector->key_len > HMAC_KDF_MAX_KEY_LEN ||
	    vector->msg_len > HMAC_KDF_MAX_MSG_LEN)
		return -EINVAL;

	memcpy(vector->key,
	       nla_data(tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_KEY]),
	       vector->key_len);
	memcpy(vector->msg,
	       nla_data(tb[IWL_VENDOR_FIPS_TEST_VECTOR_HMAC_KDF_MSG]),
	       vector->msg_len);

	return 0;
}

static int iwl_fmac_test_fips_send_resp(struct wiphy *wiphy,
					struct iwl_fmac_test_fips_resp *resp)
{
	struct sk_buff *skb;

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(*resp));
	if (!skb)
		return -ENOMEM;

	if (resp->status == IWL_FMAC_TEST_FIPS_STATUS_SUCCESS &&
	    nla_put(skb, IWL_MVM_VENDOR_ATTR_FIPS_TEST_RESULT, resp->len,
		    resp->buf)) {
		kfree_skb(skb);
		return -ENOBUFS;
	}

	return cfg80211_vendor_cmd_reply(skb);
}

static int iwl_fmac_test_fips(struct wiphy *wiphy, struct wireless_dev *wdev,
			      const void *data, int data_len)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct nlattr **tb;
	struct iwl_host_cmd hcmd = {
		.id = iwl_cmd_id(FMAC_TEST_FIPS, FMAC_GROUP, 0),
		.flags = CMD_WANT_SKB,
		.dataflags = { IWL_HCMD_DFL_NOCOPY, },
	};
	struct iwl_fmac_test_fips_cmd cmd;
	struct iwl_fmac_test_fips_resp *resp;
	int ret;
	struct nlattr *vector;
	int (*handler)(struct iwl_fmac_test_fips_cmd *cmd,
		       struct nlattr *test_vector);

	tb = iwl_fmac_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (tb[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA]) {
		cmd.type = IWL_FMAC_FIPS_TEST_SHA;
		handler = iwl_fmac_build_sha_cmd;
		vector = tb[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_SHA];
	} else if (tb[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC]) {
		cmd.type = IWL_FMAC_FIPS_TEST_HMAC;
		handler = iwl_fmac_build_hmac_kdf_cmd;
		vector = tb[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_HMAC];
	} else if (tb[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF]) {
		cmd.type = IWL_FMAC_FIPS_TEST_KDF;
		handler = iwl_fmac_build_hmac_kdf_cmd;
		vector = tb[IWL_MVM_VENDOR_ATTR_FIPS_TEST_VECTOR_KDF];
	} else {
		ret = -EINVAL;
		goto free;
	}

	ret = handler(&cmd, vector);
	if (ret)
		goto free;

	hcmd.data[0] = &cmd;
	hcmd.len[0] = sizeof(cmd);

	mutex_lock(&fmac->mutex);
	ret = iwl_fmac_send_cmd(fmac, &hcmd);
	mutex_unlock(&fmac->mutex);

	if (ret)
		goto free;

	resp = (void *)((struct iwl_rx_packet *)hcmd.resp_pkt)->data;
	iwl_fmac_test_fips_send_resp(wiphy, resp);
	iwl_free_resp(&hcmd);

free:
	kfree(tb);
	return ret;
}

static int iwl_fmac_connect_params(struct wiphy *wiphy,
				   struct wireless_dev *wdev, const void *data,
				   int data_len)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct nlattr **tb;
	struct nlattr *attr, *bssid_list;
	struct iwl_fmac_connect_params *params = &fmac->connect_params;
	int ret, tmp;

	tb = iwl_fmac_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);

	if (tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_BLACKLIST] &&
	    tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_WHITELIST]) {
		ret = -EINVAL;
		goto free;
	}

	memset(params, 0, sizeof(*params));

	if (tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_MAX_RETRIES])
		params->max_retries =
			nla_get_u8(tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_MAX_RETRIES]);

	if (tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_WHITELIST]) {
		bssid_list =
			tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_WHITELIST];
		params->is_whitelist = true;
	} else if (tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_BLACKLIST]) {
		bssid_list =
			tb[IWL_MVM_VENDOR_ATTR_FMAC_CONNECT_PARAMS_BLACKLIST];
	} else {
		ret = 0;
		goto free;
	}

	nla_for_each_nested(attr, bssid_list, tmp) {
		if (params->n_bssids >= IWL_FMAC_MAX_BSSIDS) {
			ret = -EINVAL;
			goto free;
		}

		memcpy(&params->bssids[params->n_bssids * ETH_ALEN],
		       nla_data(attr), ETH_ALEN);
		params->n_bssids++;
	}

	ret = 0;
free:
	kfree(tb);
	return ret;
}

#define FMAC_CONFIG_STR_MAX_LEN	100

static int iwl_fmac_config(struct wiphy *wiphy, struct wireless_dev *wdev,
			   const void *data, int data_len)
{
	struct iwl_fmac *fmac = iwl_fmac_from_wiphy(wiphy);
	struct iwl_fmac_vif *vif = vif_from_wdev(wdev);
	struct nlattr **tb;
	u8 config_str[FMAC_CONFIG_STR_MAX_LEN] = {0};
	int ret;
	int len;

	BUILD_BUG_ON(sizeof(config_str) % 4);

	tb = iwl_fmac_parse_vendor_data(data, data_len);
	if (IS_ERR(tb))
		return PTR_ERR(tb);
	if (!tb[IWL_MVM_VENDOR_ATTR_FMAC_CONFIG_STR]) {
		ret = -EINVAL;
		goto free;
	}

	len = nla_len(tb[IWL_MVM_VENDOR_ATTR_FMAC_CONFIG_STR]);
	if (len >= FMAC_CONFIG_STR_MAX_LEN) {
		ret = -EINVAL;
		goto free;
	}

	memcpy(config_str, nla_data(tb[IWL_MVM_VENDOR_ATTR_FMAC_CONFIG_STR]),
	       len);

	ret = iwl_fmac_send_config_cmd(fmac, vif->id,
				       IWL_FMAC_CONFIG_WPAS_GLOBAL, config_str,
				       sizeof(config_str));
free:
	kfree(tb);
	return ret;
}

static const struct wiphy_vendor_command iwl_fmac_vendor_commands[] = {
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_SET_COUNTRY,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_NETDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_fmac_set_country,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_TEST_FIPS,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_fmac_test_fips,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_FMAC_CONNECT_PARAMS,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_fmac_connect_params,
	},
	{
		.info = {
			.vendor_id = INTEL_OUI,
			.subcmd = IWL_MVM_VENDOR_CMD_FMAC_CONFIG,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = iwl_fmac_config,
	},


};

void iwl_fmac_set_wiphy_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = iwl_fmac_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(iwl_fmac_vendor_commands);
	wiphy->vendor_events = NULL;
	wiphy->n_vendor_events = 0;
}

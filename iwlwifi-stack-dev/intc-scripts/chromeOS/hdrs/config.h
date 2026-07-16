/******************************************************************************
 *
 * Copyright(c) 2018-2025 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *****************************************************************************/
#ifndef __IWL_CHROME_CONFIG
#define __IWL_CHROME_CONFIG
/* This must match the CPTCFG_* symbols defined in the Makefile */
#define CPTCFG_MAC80211_MODULE 1
#define CPTCFG_MAC80211_LEDS 1
#define CPTCFG_MAC80211_RC_DEFAULT ""
#define CPTCFG_MAC80211_STA_HASH_MAX_SIZE 0
#define CPTCFG_IWLWIFI_MODULE 1
#define CPTCFG_IWLMVM_MODULE 1

#ifdef CONFIG_IWL7000_MLD_MODULE
#define CPTCFG_IWLMLD_MODULE 1
#endif

#define CPTCFG_IWLWIFI_OPMODE_MODULAR 1
#define CPTCFG_IWLWIFI_DEBUG 1
#define CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES 1
#define CPTCFG_IWLWIFI_FW_MISBEHAVE_NMI_DEFAULT 0
#define CPTCFG_IWLWIFI_DISALLOW_OLDER_FW 1
#define CPTCFG_IWLWIFI_ATLAS_PLATFORM_WORKAROUND 1
#define CPTCFG_IWLWIFI_DEVICE_TESTMODE 1

#ifdef CONFIG_IWL7000_DEBUGFS
#define CPTCFG_MAC80211_DEBUGFS 1
#define CPTCFG_IWLWIFI_DEBUGFS 1
#define HACK_IWLWIFI_DEBUGFS_IWLMVM_SYMLINK 1
#endif

#ifdef CONFIG_IWL7000_LEDS
#define CPTCFG_IWLWIFI_LEDS 1
#endif

#ifdef CONFIG_IWL7000_TRACING
#define CPTCFG_MAC80211_MESSAGE_TRACING 1
#define CPTCFG_IWLWIFI_DEVICE_TRACING 1
#endif

#ifdef CONFIG_IWL7000_XVT_MODULE
#define CPTCFG_IWLXVT_MODULE 1
#endif

#if defined(CONFIG_IWL7000_VENDOR_CMDS)
#define CPTCFG_IWL_VENDOR_CMDS 1
#endif

#define CPTCFG_IWLWIFI_DONT_DUMP_FIFOS 1

#endif

/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2020-2021, 2023-2025 Intel Corporation
 */
#ifndef __iwl_fw_api_rfi_h__
#define __iwl_fw_api_rfi_h__

#define IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM 15
#define IWL_RFI_DDR_LUT_SIZE 44
#define IWL_RFI_DDR_LUT_INSTALLED_SIZE 4
#define IWL_RFI_DLVR_LUT_ENTRY_CHANNELS_NUM 36
#define IWL_RFI_DLVR_LUT_INSTALLED_SIZE 4

#define IWL_RFI_MAX_FREQ_VAL 961
#define IWL_RFI_MAX_ALLOWED_CHAN 237
#define IWL_RFI_MAX_SNR_THRESHOLD 100
#define IWL_RFI_MAX_DESENSE 80

/**
 * struct iwl_rfi_ddr_lut_entry - an entry in the RFI DDR frequency LUT.
 *
 * @freq: frequency
 * @channels: channels that can be interfered at frequency freq (at most 15)
 * @bands: the corresponding bands
 */
struct iwl_rfi_ddr_lut_entry {
	__le16 freq;
	u8 channels[IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM];
	u8 bands[IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM];
} __packed;

/**
 * struct iwl_rfi_desense_lut_entry - an entry in the RFI DDR DESENSE LUT.
 *
 * @chain_a: positive dB value for chain a.
 * @chain_b: positive dB value for chain b.
 */
struct iwl_rfi_desense_lut_entry {
	u8 chain_a[IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM];
	u8 chain_b[IWL_RFI_DDR_LUT_ENTRY_CHANNELS_NUM];
} __packed;

/**
 * struct iwl_rfi_dlvr_lut_entry - an entry in the RFI DLVR frequency LUT.
 *
 * @freq: DLVR frequency
 * @channels: channels that can be interfered at frequency freq (at most 36)
 * @bands: the corresponding bands
 * @reserved: reserved for DW alignment
 */
struct iwl_rfi_dlvr_lut_entry {
	__le16 freq;
	u8 channels[IWL_RFI_DLVR_LUT_ENTRY_CHANNELS_NUM];
	u8 bands[IWL_RFI_DLVR_LUT_ENTRY_CHANNELS_NUM];
	u8 reserved[2];
} __packed;

/**
 * enum rfi_memory_support_mask - memory support masks used in RFI_CONFIG_CMD
 *
 * @RFI_DDR_SUPPORTED_MSK: enable DDR support
 * @RFI_DLVR_SUPPORTED_MSK: enable DLVR support
 * @RFI_DESENSE_SUPPORTED_MSK: enable desense support
 */
enum rfi_memory_support_mask {
	RFI_DDR_SUPPORTED_MSK		= BIT(0),
	RFI_DLVR_SUPPORTED_MSK		= BIT(1),
	RFI_DESENSE_SUPPORTED_MSK	= BIT(2),
};

/**
 * struct iwl_rfi_config_cmd_v3 - RFI configuration table
 *
 * @rfi_memory_support: memory support mask @enum rfi_memory_support_mask
 * @ddr_table: a table of channels that are used by DDR
 * @oem: specifies if this is the default table or set by OEM
 * @reserved: (reserved/padding)
 */
struct iwl_rfi_config_cmd_v3 {
	__le32 rfi_memory_support;
	struct iwl_rfi_ddr_lut_entry ddr_table[IWL_RFI_DDR_LUT_SIZE];
	u8 oem;
	u8 reserved[3];
} __packed; /* RFI_CONFIG_CMD_API_S_VER_3 */

#define IWL_RFI_DDR_DESENSE_VALUE 10
#define IWL_RFI_DDR_SNR_THRESHOLD 68

/**
 * struct iwl_rfi_config_cmd - RFI configuration table
 *
 * @rfi_memory_support: memory support mask @enum rfi_memory_support_mask
 * @ddr_table: a table of channels that are used by DDR
 * @oem: specifies if this is the default table or set by OEM
 * @reserved: (reserved/padding)
 * @snr_threshold: SNR threshold to be used for RSSI based RFIM.
 * @desense_table: desense values per chain. see &iwl_rfi_desense_lut_entry
 */
struct iwl_rfi_config_cmd {
	__le32 rfi_memory_support;
	struct iwl_rfi_ddr_lut_entry ddr_table[IWL_RFI_DDR_LUT_SIZE];
	u8 oem;
	u8 reserved[3];
	__le32 snr_threshold;
	struct iwl_rfi_desense_lut_entry desense_table[IWL_RFI_DDR_LUT_SIZE];
} __packed; /* RFI_CONFIG_CMD_API_S_VER_4 */

/**
 * enum iwl_rfi_freq_table_status - status of the frequency table query
 * @RFI_FREQ_TABLE_OK: can be used
 * @RFI_FREQ_TABLE_DVFS_NOT_READY: DVFS is not ready yet, should try later
 * @RFI_FREQ_DDR_TABLE_DISABLED: DDR feature is disabled in FW
 * @RFI_FREQ_DLVR_TABLE_DISABLED: DLVR feature is disabled in FW
 * @RFI_FREQ_ALL_TABLES_DISABLED: DDR, DLVR features are disabled in FW
 */
enum iwl_rfi_freq_table_status {
	RFI_FREQ_TABLE_OK,
	RFI_FREQ_TABLE_DVFS_NOT_READY,
	RFI_FREQ_DDR_TABLE_DISABLED,
	RFI_FREQ_DLVR_TABLE_DISABLED,
	RFI_FREQ_ALL_TABLES_DISABLED,
};

/**
 * struct iwl_rfi_freq_table_resp_cmd_v1 - get the rfi freq table used by FW
 *
 * @ddr_table: DDR table used by FW &iwl_rfi_ddr_lut_entry.
 * @status: see &iwl_rfi_freq_table_status
 */
struct iwl_rfi_freq_table_resp_cmd_v1 {
	struct iwl_rfi_ddr_lut_entry ddr_table[IWL_RFI_DDR_LUT_INSTALLED_SIZE];
	__le32 status;
} __packed; /* RFI_CONFIG_CMD_API_S_VER_1 */

/**
 * struct iwl_rfi_freq_table_resp_cmd_v2 - get the rfi freq tables used by FW
 *
 * @ddr_table: DDR table used by FW &iwl_rfi_ddr_lut_entry.
 * @status: see &iwl_rfi_freq_table_status
 * @dlvr_table: DLVR table used by FW &iwl_rfi_dlvr_lut_entry.
 */
struct iwl_rfi_freq_table_resp_cmd_v2 {
	struct iwl_rfi_ddr_lut_entry ddr_table[IWL_RFI_DDR_LUT_INSTALLED_SIZE];
	__le32 status;
	struct iwl_rfi_dlvr_lut_entry dlvr_table[IWL_RFI_DLVR_LUT_INSTALLED_SIZE];
} __packed; /* RFI_CONFIG_CMD_API_S_VER_2 */

/**
 * struct iwl_rfi_freq_table_resp_cmd - get the rfi freq tables used by FW
 *
 * @ddr_table: DDR table used by FW
 * @status: see &iwl_rfi_freq_table_status
 * @dlvr_table: DLVR table used by FW
 * @desense_table: De-sense table used by FW
 */
struct iwl_rfi_freq_table_resp_cmd {
	struct iwl_rfi_ddr_lut_entry ddr_table[IWL_RFI_DDR_LUT_INSTALLED_SIZE];
	__le32 status;
	struct iwl_rfi_dlvr_lut_entry dlvr_table[IWL_RFI_DLVR_LUT_INSTALLED_SIZE];
	struct iwl_rfi_desense_lut_entry desense_table[IWL_RFI_DDR_LUT_INSTALLED_SIZE];
} __packed; /* RFI_CONFIG_CMD_API_S_VER_3 */

/**
 * enum iwl_rfi_support_reason - indicate error or pmc supported
 *
 * @IWL_RFI_RESET_FAILURE_SEND_TO_PEER: Failure due to send to peer
 * @IWL_RFI_RESET_FAILURE_PLAT_PSS: Failure due to Plat pss
 * @IWL_RFI_RESET_FAILURE_TIMER: Failure due to timer
 * @IWL_RFI_MAX_RESETS_DONE: Failure due to max resets
 * @IWL_RFI_PMC_SUPPORTED: PMC supported
 * @IWL_RFI_PMC_NOT_SUPPORTED: PMC not supported
 * @IWL_RFI_DDR_SUBSET_TABLE_READY: PMC supported and DDR subset table is ready
 */
enum iwl_rfi_support_reason {
	IWL_RFI_RESET_FAILURE_SEND_TO_PEER,
	IWL_RFI_RESET_FAILURE_PLAT_PSS,
	IWL_RFI_RESET_FAILURE_TIMER,
	IWL_RFI_MAX_RESETS_DONE,
	IWL_RFI_PMC_SUPPORTED,
	IWL_RFI_PMC_NOT_SUPPORTED,
	IWL_RFI_DDR_SUBSET_TABLE_READY,
};

/**
 * struct iwl_rfi_support_notif - notifcation that FW disaled RFIm
 *
 * @reason: PMC support or deactivate reason &enum iwl_rfi_support_reason
 */
struct iwl_rfi_support_notif {
	__le32 reason;
} __packed; /* RFI_SUPPORT_NTF_S_VER_1 */
#endif /* __iwl_fw_api_rfi_h__ */

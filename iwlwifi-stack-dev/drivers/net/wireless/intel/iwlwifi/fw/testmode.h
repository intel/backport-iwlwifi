/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2013-2014, 2018, 2023, 2025 Intel Corporation
 * Copyright (C) 2013-2014 Intel Mobile Communications GmbH
 */
#ifndef __IWL_TESTMODE_H__
#define __IWL_TESTMODE_H__

#ifdef CPTCFG_IWLWIFI_DEVICE_TESTMODE
struct iwl_host_cmd;
struct iwl_rx_cmd_buffer;

struct iwl_testmode {
	struct iwl_trans *trans;
	const struct iwl_fw *fw;
	/* the mutex of the op_mode */
	struct mutex *mutex;
	void *op_mode;
	int (*send_hcmd)(void *op_mode, struct iwl_host_cmd *host_cmd);
	u32 fw_major_ver;
	u32 fw_minor_ver;
};

/**
 * struct iwl_tm_data - A data packet for testmode usages
 * @data:   Pointer to be casted to relevant data type
 *          (According to usage)
 * @len:    Size of data in bytes
 *
 * This data structure is used for sending/receiving data packets
 * between internal testmode interfaces
 */
struct iwl_tm_data {
	void *data;
	u32 len;
};

void iwl_tm_init(struct iwl_trans *trans, const struct iwl_fw *fw,
		 struct mutex *mutex, void *op_mode);

void iwl_tm_set_fw_ver(struct iwl_trans *trans, u32 fw_major_ver,
		       u32 fw_minor_var);

int iwl_tm_execute_cmd(struct iwl_testmode *testmode, u32 cmd,
		       struct iwl_tm_data *data_in,
		       struct iwl_tm_data *data_out);

#define ADDR_IN_AL_MSK (0x80000000)
#define GET_AL_ADDR(ofs) (ofs & ~(ADDR_IN_AL_MSK))
#define IS_AL_ADDR(ofs) (!!(ofs & (ADDR_IN_AL_MSK)))
#endif

#endif /* __IWL_TESTMODE_H__ */

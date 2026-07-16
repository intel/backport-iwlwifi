/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#ifndef __iwl_prod_h__
#define __iwl_prod_h__

#include "iwl-trans.h"
#include "iwl-op-mode.h"
#include "fw/img.h"
#include "fw/runtime.h"

/**
 * enum iwl_prod_status - prod status bits
 * @IWL_PROD_STATUS_FIRMWARE_RUNNING: firmware is running
 */
enum iwl_prod_status {
	IWL_PROD_STATUS_FIRMWARE_RUNNING,
};

/**
 * struct iwl_prod - the production op_mode
 *
 * @trans: pointer to the transport layer
 * @cfg: pointer to the device configuration
 * @fw: a pointer to the fw object
 * @dev: pointer to struct device for printing purposes
 * @status: prod status bit flags. see enum &iwl_prod_status
 * @fwrt: runtime data for firmware
 */
struct iwl_prod {
	struct iwl_trans *trans;
	const struct iwl_rf_cfg *cfg;
	const struct iwl_fw *fw;
	struct device *dev;
	unsigned long status;
	struct iwl_fw_runtime fwrt;
};

#define IWL_OP_MODE_GET_PROD(_op_mode) \
	((struct iwl_prod *)((_op_mode)->op_mode_specific))

#define IWL_FWRT_DUMP_PRODUCTION_TYPE	0x6

int iwl_prod_run_fw(struct iwl_prod *prod);
void iwl_prod_stop_device(struct iwl_prod *prod);
void iwl_prod_fatal_error(struct iwl_prod *prod);

static inline bool iwl_prod_firmware_running(struct iwl_prod *prod)
{
	return test_bit(IWL_PROD_STATUS_FIRMWARE_RUNNING, &prod->status);
}

#ifdef CPTCFG_IWLWIFI_DEBUGFS
int iwl_prod_dbgfs_register(struct iwl_prod *prod, struct dentry *dbgfs_dir);
#else
static inline int iwl_prod_dbgfs_register(struct iwl_prod *prod,
					  struct dentry *dbgfs_dir)
{
	WARN_ONCE(1, "iwlprod must have debugfs support\n");
	return -1;
}
#endif /* CPTCFG_IWLWIFI_DEBUGFS */

int iwl_smart_tester_get_cmd_timeout(struct iwl_prod *prod, u32 cmd_id);
int iwl_smart_tester_wait_for_rsp(struct iwl_prod *prod, u32 cmd_id);
int iwl_smart_tester_send_cmd(struct iwl_prod *prod,
			      struct iwl_smart_tester_cmd_rsp *cmd);
void iwl_smart_tester_dump_error(struct iwl_prod *prod, bool *is_valid_err);

#endif /* __iwl_prod_h__ */

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#include "prod.h"
#include "fw/dbg.h"
#include "fw/api/smart-tester.h"

static int iwl_prod_load_ucode_wait_alive(struct iwl_prod *prod)
{
	enum iwl_ucode_type ucode_type = IWL_UCODE_REGULAR;
	int ret;

	clear_bit(IWL_PROD_STATUS_FIRMWARE_RUNNING, &prod->status);

	iwl_fw_set_current_image(&prod->fwrt, ucode_type);

	ret = iwl_trans_start_fw(prod->trans, prod->fw, ucode_type, true);
	if (ret)
		return ret;

	set_bit(IWL_PROD_STATUS_FIRMWARE_RUNNING, &prod->status);

	/* driver should not send the INIT_CONFIG_CMD but only wait for the
	 * equivalent "INIT_COMPLETE" response after starting the fw.
	 */
	ret = iwl_smart_tester_wait_for_rsp(prod, SMART_TESTER_INIT_CONFIG_CMD);
	if (ret) {
		IWL_ERR(prod, "Prod: init complete fail %d\n", ret);
		return ret;
	}

	IWL_DEBUG_FW(prod, "Prod: Got INIT_COMPLETE response\n");

	iwl_trans_fw_alive(prod->trans);

	return 0;
}

int iwl_prod_run_fw(struct iwl_prod *prod)
{
	int ret;

	ret = iwl_trans_start_hw(prod->trans);
	if (ret) {
		IWL_ERR(prod, "Prod: Failed to start HW: %d\n", ret);
		return ret;
	}

	iwl_dbg_tlv_time_point(&prod->fwrt, IWL_FW_INI_TIME_POINT_EARLY,
			       NULL);

	ret = iwl_prod_load_ucode_wait_alive(prod);
	if (ret) {
		IWL_ERR(prod, "Prod: Failed to start uCode: %d\n", ret);
		iwl_prod_fatal_error(prod);
		return ret;
	}

	iwl_dbg_tlv_time_point(&prod->fwrt, IWL_FW_INI_TIME_POINT_AFTER_ALIVE,
			       NULL);
	iwl_dbg_tlv_time_point(&prod->fwrt, IWL_FW_INI_TIME_POINT_POST_INIT,
			       NULL);

	return 0;
}

void iwl_prod_fatal_error(struct iwl_prod *prod)
{
	bool is_valid_error = false;

	/* dump HW SMEM error buffer */
	iwl_smart_tester_dump_error(prod, &is_valid_error);

	/* dump error tables */
	iwl_fwrt_dump_error_logs(&prod->fwrt);

	/* if HW SMEM error buffer header is_valid bit is set, it means that
	 * firmware is already in assert, so no need to execute nmi
	 */
	if (!is_valid_error) {
		IWL_DEBUG_FW(prod,
			     "Prod: force nmi before fw dump collection\n");
		iwl_force_nmi(prod->trans);
		/* there are no interrupts so we need to wait a bit and then
		 * trigger firmware dump collection
		 */
		mdelay(5);
	}

	set_bit(STATUS_FW_ERROR, &prod->trans->status);

	iwl_fw_error_collect(&prod->fwrt);

	/* we don't need to reset the device - just stop it and let userspace
	 * to determine whether to unload the driver or restart firmware
	 */
	iwl_prod_stop_device(prod);
}

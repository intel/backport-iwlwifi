// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#include <linux/module.h>

#include "prod.h"
#include "fw/dbg.h"
#include "iwl-trans.h"

#define DRV_DESCRIPTION "Intel(R) Production driver for Linux"
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_LICENSE("GPL");
#if LINUX_VERSION_IS_LESS(6,13,0)
MODULE_IMPORT_NS(IWLWIFI);
#else
MODULE_IMPORT_NS("IWLWIFI");
#endif /* LINUX_VERSION_IS_LESS(6,13,0) */

static const struct iwl_op_mode_ops iwl_prod_ops;

static int __init iwl_prod_init(void)
{
	return iwl_opmode_register("iwlprod", &iwl_prod_ops);
}
module_init(iwl_prod_init);

static void __exit iwl_prod_exit(void)
{
	iwl_opmode_deregister("iwlprod");
}
module_exit(iwl_prod_exit);

void iwl_prod_stop_device(struct iwl_prod *prod)
{
	if (!iwl_prod_firmware_running(prod))
		return;

	iwl_trans_stop_device(prod->trans);
	clear_bit(IWL_PROD_STATUS_FIRMWARE_RUNNING, &prod->status);
}

static void iwl_prod_stop_op_mode(struct iwl_prod *prod)
{
	iwl_fw_runtime_free(&prod->fwrt);
	iwl_prod_stop_device(prod);
	iwl_trans_op_mode_leave(prod->trans);
	clear_bit(STATUS_DISABLE_HCMD, &prod->trans->status);
}

static void iwl_prod_nic_config(struct iwl_op_mode *op_mode)
{
	/* required for IWL_DEVICE_FAMILY_22000 and older */
}

static void iwl_prod_nic_error(struct iwl_op_mode *op_mode,
			       enum iwl_fw_error_type type)
{
	struct iwl_prod *prod = IWL_OP_MODE_GET_PROD(op_mode);

	/* for now only print the registers error logs */
	iwl_fwrt_dump_error_logs(&prod->fwrt);
}

static void iwl_prod_rx(struct iwl_op_mode *op_mode, struct napi_struct *napi,
			struct iwl_rx_cmd_buffer *rxb)
{
	/* we're not expecting to get Rx, add a warning in such case */
	WARN_ONCE(1, "Got unexpected Rx\n");
}

static int iwl_prod_verify_smart_tester(struct iwl_trans *trans,
					const struct iwl_fw *fw)
{
	const struct iwl_smart_tester *tester = &fw->smart_tester;
	u32 cmd_rsp_size = sizeof(struct iwl_smart_tester_cmd_rsp);
	u32 err_size = sizeof(struct iwl_smart_tester_err);

	if (!tester->cmds_timeout || !tester->n_cmds_timeout) {
		IWL_ERR(trans, "Invalid cmds timeout table\n");
		return -EINVAL;
	}

	if (le32_to_cpu(tester->smem.cmd_size) < cmd_rsp_size) {
		IWL_ERR(trans, "Invalid cmd size (exp=0x%x actual=0x%x)\n",
			tester->smem.cmd_size, cmd_rsp_size);
		return -EINVAL;
	}

	if (le32_to_cpu(tester->smem.rsp_size) < cmd_rsp_size) {
		IWL_ERR(trans, "Invalid rsp size (exp=0x%x actual=0x%x)\n",
			tester->smem.rsp_size, cmd_rsp_size);
		return -EINVAL;
	}

	if (le32_to_cpu(tester->smem.err_size) < err_size) {
		IWL_ERR(trans, "Invalid err size (exp=0x%x actual=0x%x)\n",
			tester->smem.rsp_size, err_size);
		return -EINVAL;
	}

	return 0;
}

static struct iwl_op_mode *iwl_prod_start(struct iwl_trans *trans,
					  const struct iwl_rf_cfg *cfg,
					  const struct iwl_fw *fw,
					  struct dentry *dbgfs_dir)
{
	struct iwl_op_mode *op_mode;
	struct iwl_prod *prod;
	int ret;

	/* verify smart tester related data only once at init */
	ret = iwl_prod_verify_smart_tester(trans, fw);
	if (ret)
		return ERR_PTR(ret);

	op_mode = kzalloc(sizeof(*op_mode) + sizeof(*prod), GFP_KERNEL);
	if (!op_mode)
		return ERR_PTR(-ENOMEM);

	op_mode->ops = &iwl_prod_ops;

	prod = IWL_OP_MODE_GET_PROD(op_mode);
	prod->fw = fw;
	prod->cfg = cfg;
	prod->trans = trans;
	prod->dev = trans->dev;

	iwl_fw_runtime_init(&prod->fwrt, trans, fw, NULL, prod,
			    NULL, NULL, dbgfs_dir);
	/* in operational driver fw_ver.type (uCodeBuildType) is taken from
	 * alive notification lmac1 data but in production mode we just set it
	 * to a hardcoded value. This is needed for debug tools to locate the
	 * correct production DEV_TRACE.
	 */
	prod->fwrt.dump.fw_ver.type = IWL_FWRT_DUMP_PRODUCTION_TYPE;

	IWL_INFO(prod, "iwlprod operation mode\n");

	/*
	 * Populate the state variables that the transport layer needs
	 * to know about.
	 */
	/* we don't have Rx flows (use a dummy value as it's required) */
	trans->conf.rx_buf_size = IWL_AMSDU_4K;

	/* we don't have regular hcmds (silence a warning) */
	trans->conf.rx_mpdu_cmd = REPLY_RX_MPDU_CMD;

	/* production uCode does not support the regular HCMD mechanisem */
	set_bit(STATUS_DISABLE_HCMD, &trans->status);

	iwl_trans_op_mode_enter(prod->trans, op_mode);

	ret = iwl_prod_dbgfs_register(prod, dbgfs_dir);
	if (ret)
		goto out_free;

	return op_mode;

out_free:
	iwl_fw_runtime_free(&prod->fwrt);
	iwl_trans_op_mode_leave(trans);
	kfree(op_mode);
	return ERR_PTR(ret);
}

static void iwl_prod_stop(struct iwl_op_mode *op_mode)
{
	struct iwl_prod *prod = IWL_OP_MODE_GET_PROD(op_mode);

	iwl_prod_stop_op_mode(prod);

	kfree(op_mode);
}

static const struct iwl_op_mode_ops iwl_prod_ops = {
	.start = iwl_prod_start,
	.stop = iwl_prod_stop,
	.nic_config = iwl_prod_nic_config,
	.nic_error = iwl_prod_nic_error,
	.rx = iwl_prod_rx,
};

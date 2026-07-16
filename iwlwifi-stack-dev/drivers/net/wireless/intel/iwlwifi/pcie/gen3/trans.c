// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#ifdef CPTCFG_IWLWIFI_SIMULATION
#include <linux/vmalloc.h>
#endif

#include "fw/api/tx.h"
#include "trans.h"
#include "interrupts.h"
#include "iwl-debug.h"
#include "iwl-io.h"
#include "iwl-trans.h"
#include "iwl-prph.h"

static int iwl_pcie_gen3_take_hw_ownership_semaphore(struct iwl_trans *trans)
{
	int err;

	IWL_DEBUG_INFO(trans,
		       "Trying to take NIC ownership semaphore from ME\n");

	iwl_set_bit(trans, CSR_HW_IF_CONFIG_REG,
		    CSR_HW_IF_CONFIG_REG_PCI_OWN_SET);

	/* Check if we succeed to take the ownership */
	err = iwl_poll_bits(trans, CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_PCI_OWN_SET,
			    50);

	IWL_DEBUG_INFO(trans, "Current NIC owner: %s\n", err ? "ME" : "Host");
	return err;
}

static int iwl_pcie_gen3_acquire_hw_ownership(struct iwl_trans *trans)
{
	int err;
	int overall_time = 0;
	/* Time values are specified in microseconds (us) */
	const int max_loop_time = 750000;
	const int max_overall_time = 66000000 + max_loop_time;

	/*
	 * According to the requirements, ME may own the NIC
	 * and block the driver from taking ownership.
	 * Setting WAKE_ME bit will trigger a request from ME to release the NIC
	 * There are 4 cases:
	 *
	 * 1. ME is not the owner: we get ownership immediately.
	 * 2. ME releases ownership willingly when it can.
	 * 3. ME is not responding: we wait for timeout to get the ownership.
	 * 4. ME is the owner and refuses to release ownership.
	 *
	 * It can take up to 65.5 seconds (timeout) to get a response from ME.
	 */

	while (overall_time < max_overall_time) {
		int loop_time = 0;

		IWL_DEBUG_INFO(trans, "Requesting ME to release ownership\n");

		iwl_set_bit(trans, CSR_HW_IF_CONFIG_REG,
			    CSR_HW_IF_CONFIG_REG_WAKE_ME);

		while (loop_time < max_loop_time) {
			usleep_range(200, 1000);
			loop_time += 200;

			err = iwl_pcie_gen3_take_hw_ownership_semaphore(trans);
			if (!err)
				return 0;
		}

		msleep(25);
		overall_time += 25 * 1000 + loop_time;
	}

	IWL_ERR(trans,
		"Failed to take ownership from ME, ME is the owner and refuses to release ownership.\n");

	return err;
}

static void iwl_pcie_gen3_free(struct iwl_trans *trans)
{
	iwl_trans_free(trans);
}

static struct iwl_trans *iwl_alloc_pcie_gen3(struct pci_dev *pdev,
					     const struct iwl_mac_cfg *mac_cfg,
					     u8 __iomem *hw_base)
{
	struct iwl_pcie_gen3 *trans_pcie;
	struct iwl_trans *trans;

	trans = iwl_trans_alloc(sizeof(struct iwl_pcie_gen3), &pdev->dev,
				mac_cfg);
	if (!trans)
		return ERR_PTR(-ENOMEM);

	trans_pcie = IWL_GET_PCIE_GEN3(trans);

	trans_pcie->trans = trans;
	trans_pcie->hw_base = hw_base;
	trans_pcie->pci_dev = pdev;

	spin_lock_init(&trans_pcie->reg_lock);

	iwl_dbg_tlv_init(trans);

	return trans;
}

static int iwl_pcie_gen3_build_hw_rf_id(struct iwl_trans *trans)
{
	IWL_ERR(trans, " %s NOT IMPLEMENTED\n", __func__);
	return -EOPNOTSUPP;
}

static int iwl_pcie_gen3_init_hw_info(struct iwl_trans *trans,
				      struct iwl_trans_info *info, u32 hw_rev)
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);
	struct pci_dev *pdev = trans_pcie->pci_dev;
	u32 tmp, hw_wfpm_id;
	u8 step;

	info->hw_id = (pdev->device << 16) + pdev->subsystem_device,
	info->hw_rev = hw_rev;
	info->hw_rev_step = info->hw_rev & 0xF;
	info->hw_rf_id = iwl_read32(trans, CSR_HW_RF_ID);
	/* TODO: info->max_skb_frags (task = tx) */

	if (!trans->mac_cfg->integrated) {
		u16 link_status;

		pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &link_status);

		info->pcie_link_speed =
			u16_get_bits(link_status, PCI_EXP_LNKSTA_CLS);
	}

	/* Enable access to peripheral registers */
	tmp = iwl_read_umac_prph_no_grab(trans, WFPM_CTRL_REG);
	tmp |= WFPM_AUX_CTL_AUX_IF_MAC_OWNER_MSK;
	iwl_write_umac_prph_no_grab(trans, WFPM_CTRL_REG, tmp);

	/* Read crf info */
	info->hw_crf_id = iwl_read_prph_no_grab(trans, SD_REG_VER_GEN2);

	/* Read cnv info */
	info->hw_cnv_id = iwl_read_prph_no_grab(trans, CNVI_AUX_MISC_CHIP);

	/* For BZ-W, take B step also when A step is indicated */
	if (CSR_HW_REV_TYPE(info->hw_rev) == IWL_CFG_MAC_TYPE_BZ_W)
		step = SILICON_B_STEP;

	/* In BZ, the MAC step must be read from the CNVI aux register */
	if (CSR_HW_REV_TYPE(info->hw_rev) == IWL_CFG_MAC_TYPE_BZ) {
		step = CNVI_AUX_MISC_CHIP_MAC_STEP(info->hw_cnv_id);

		/* For BZ-U, take B step also when A step is indicated */
		if ((CNVI_AUX_MISC_CHIP_PROD_TYPE(info->hw_cnv_id) ==
		    CNVI_AUX_MISC_CHIP_PROD_TYPE_BZ_U) &&
		    step == SILICON_A_STEP)
			step = SILICON_B_STEP;
	}

	if (CSR_HW_REV_TYPE(info->hw_rev) == IWL_CFG_MAC_TYPE_BZ ||
	    CSR_HW_REV_TYPE(info->hw_rev) == IWL_CFG_MAC_TYPE_BZ_W) {
		info->hw_rev_step = step;
		info->hw_rev |= step;
	}

	hw_wfpm_id = iwl_read_umac_prph_no_grab(trans, WFPM_OTP_CFG1_ADDR);

#ifdef CPTCFG_IWLWIFI_NJ_SUPPORT
	/*
	 * Note: if NIC access fails this is false: WFPM_OTP_CFG1_IS_JACKET_BIT
	 * is BIT(5) which isn't set in the default value of 0x5a5a5a5a.
	 */
	info->is_jacket = WFPM_OTP_CFG1_IS_JACKET(hw_wfpm_id);
#endif

	IWL_INFO(trans, "Detected hw_id 0x%x, hw_rev 0x%x hw_rev_step %d\n",
		 info->hw_id, info->hw_rev, info->hw_rev_step);
	IWL_INFO(trans, "Detected hw_cnv_id 0x%x, hw_crf_id 0x%x hw_wfpm_id 0x%x\n",
		 info->hw_cnv_id, info->hw_crf_id, hw_wfpm_id);

	/* Blank OTP. Build hw_rf_id from hw_crf_id */
	if (!CSR_HW_RFID_TYPE(info->hw_rf_id))
		return iwl_pcie_gen3_build_hw_rf_id(trans);

	return 0;
}

static bool iwl_pcie_gen3_nic_is_ok(struct iwl_trans *trans,
				    struct iwl_trans_info *info, u32 hw_rev)
{
	int ret;

	/*
	 * Let's try to access the NIC early here. Sometimes, NICs may
	 * fail to initialize, and if that happens it's better if we see
	 * issues early on, than later when the first interface is brought up.
	 */

	ret = iwl_pcie_gen3_acquire_hw_ownership(trans);
	if (ret)
		return false;

	ret = iwl_pcie_gen3_activate_nic(trans);
	if (ret)
		return false;

	if (!iwl_trans_grab_nic_access(trans))
		return false;

	/*
	 * Ok, we are good to go.
	 * But since we already have the nic ready, let's read some information
	 * we need from its memory.
	 */
	ret = iwl_pcie_gen3_init_hw_info(trans, info, hw_rev);

	iwl_trans_release_nic_access(trans);

	return ret == 0;
}

int iwl_pci_gen3_probe(struct pci_dev *pdev,
		       const struct pci_device_id *ent,
		       const struct iwl_mac_cfg *mac_cfg, u8 __iomem *hw_base,
		       u32 hw_rev)
{
	const struct iwl_dev_info *dev_info;
#ifdef CPTCFG_IWLWIFI_SIMULATION
	struct iwl_pcie_gen3 *trans_pcie;
#endif
	struct iwl_trans_info info;
	struct iwl_trans *trans;
	int ret;

	trans = iwl_alloc_pcie_gen3(pdev, mac_cfg, hw_base);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

	IWL_INFO(trans, "PCI dev %04x/%04x\n", pdev->device,
		 pdev->subsystem_device);

#ifdef CPTCFG_IWLWIFI_PRE_SILICON_SUPPORT
	iwl_set_pre_si_factors(hw_rev);
#endif

	if (!iwl_pcie_gen3_nic_is_ok(trans, &info, hw_rev)) {
		ret = -EOPNOTSUPP;
		goto free;
	}

#if !IS_ENABLED(CPTCFG_IWLMLD)
	if (iwl_drv_is_wifi7_supported(trans)) {
		IWL_ERR(trans,
			"IWLMLD needs to be compiled to support this device\n");
		ret = -EOPNOTSUPP;
		goto free;
	}
#endif

	dev_info = iwl_pci_find_dev_info(pdev->device, pdev->subsystem_device,
					 CSR_HW_RFID_TYPE(info.hw_rf_id),
					 CSR_HW_RFID_IS_CDB(info.hw_rf_id),
					 IWL_SUBDEVICE_RF_ID(pdev->subsystem_device),
					 IWL_SUBDEVICE_BW_LIM(pdev->subsystem_device),
					 !trans->mac_cfg->integrated);
	if (!dev_info) {
		pr_err("No config found for PCI dev %04x/%04x, hw_rev=0x%x, hw_rf_id=0x%x\n",
		       pdev->device, pdev->subsystem_device,
		       info.hw_rev, info.hw_rf_id);
		ret = -EINVAL;
		goto free;
	}

	trans->cfg = dev_info->cfg;
	info.name = dev_info->name;
	IWL_INFO(trans, "Detected %s\n", info.name);

	/* info is fully set. Copy it to trans */
	iwl_trans_set_info(trans, &info);

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
		/* both attempts failed: */
		if (ret) {
			dev_err(&pdev->dev, "No suitable DMA available\n");
			goto free;
		}
	}

	pci_set_drvdata(pdev, trans);

#ifdef CPTCFG_IWLWIFI_SIMULATION
	trans_pcie = IWL_GET_PCIE_GEN3(trans);
	trans_pcie->sim_base = pcim_iomap(pdev, 2, 0);
#endif

	trans->drv = iwl_drv_start(trans);
	if (IS_ERR(trans->drv)) {
		ret = PTR_ERR(trans->drv);
		goto free;
	}

	/* TODO: add debugfs files (task = debugfs) */

	return 0;
free:
	iwl_pcie_gen3_free(trans);
	return ret;
}

void iwl_pcie_gen3_remove(struct iwl_trans *trans)
{
	iwl_drv_stop(trans->drv);

	iwl_pcie_gen3_free(trans);
}

int iwl_pcie_gen3_start_hw(struct iwl_trans *trans)
{
	IWL_ERR(trans, "%s NOT IMPLEMENTED\n", __func__);
	return -EINVAL;
}

int iwl_pcie_gen3_sw_reset(struct iwl_trans *trans, bool retake_ownership)
{
	/* Reset entire device - do controller reset (results in SHRD_HW_RST) */
	iwl_set_bit(trans, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_SW_RESET);
#ifdef CPTCFG_IWLWIFI_PRE_SILICON_SUPPORT
	usleep_range(10000 * iwl_delay_factor, 20000 * iwl_delay_factor);
#else
	usleep_range(10000, 20000);
#endif

	if (retake_ownership)
		return iwl_pcie_gen3_acquire_hw_ownership(trans);

	return 0;
}

int iwl_pcie_gen3_activate_nic(struct iwl_trans *trans)
{
	int err;

	/* Unknown W/A, leave it to avoid a risk */
	iwl_set_bit(trans, CSR_DBG_HPET_MEM_REG, CSR_DBG_HPET_MEM_REG_VAL);

	/* request MAC initialization */
	iwl_set_bit(trans, CSR_GP_CNTRL,
		    CSR_GP_CNTRL_REG_FLAG_MAC_INIT);

	/*
	 * Check the status, once it is set, we can access the MAC
	 * registers and perform operations that require MAC access,
	 * such as using iwl_write_prph() or accessing the uCode SRAM.
	 */
#ifdef CPTCFG_IWLWIFI_PRE_SILICON_SUPPORT
	err = iwl_poll_bits(trans, CSR_GP_CNTRL,
			    CSR_GP_CNTRL_REG_FLAG_MAC_STATUS,
			    25000 * iwl_timeout_factor);
#else
	err = iwl_poll_bits(trans, CSR_GP_CNTRL,
			    CSR_GP_CNTRL_REG_FLAG_MAC_STATUS, 25000);
#endif

	if (err) {
		IWL_DEBUG_INFO(trans, "Failed to initialize NIC\n");

		IWL_ERR(trans, "CSR_RESET = 0x%x\n",
			iwl_read32(trans, CSR_RESET));
	}

	return err;
}

bool iwl_trans_pcie_gen3_grab_nic_access(struct iwl_trans *trans)
{
	int ret;
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);

	if (test_bit(STATUS_TRANS_DEAD, &trans->status))
		return false;

	spin_lock(&trans_pcie->reg_lock);

	/* this bit wakes up the NIC */
	iwl_trans_set_bit(trans, CSR_GP_CNTRL,
			  CSR_GP_CNTRL_REG_FLAG_BZ_MAC_ACCESS_REQ);
	udelay(2);

	ret = iwl_poll_bits(trans, CSR_GP_CNTRL,
			    CSR_GP_CNTRL_REG_FLAG_MAC_STATUS,
			    15000);
	if (unlikely(ret < 0)) {
		u32 cntrl = iwl_read32(trans, CSR_GP_CNTRL);

		WARN_ONCE(1,
			  "Timeout waiting for hardware access (CSR_GP_CNTRL 0x%08x)\n",
			  cntrl);

		iwl_trans_pcie_dump_regs(trans, trans_pcie->pci_dev);

		if (iwlwifi_mod_params.remove_when_gone && cntrl == ~0U) {
			/* TODO: task=reset */
		} else {
			iwl_write32(trans, CSR_RESET,
				    CSR_RESET_REG_FLAG_FORCE_NMI);
		}

		spin_unlock(&trans_pcie->reg_lock);
		return false;
	}
	/*
	 * Fool sparse by faking we release the lock - sparse will
	 * track nic_access anyway.
	 */
	__release(&trans_pcie->reg_lock);
	return true;
}

void __releases(nic_access)
iwl_trans_pcie_gen3_release_nic_access(struct iwl_trans *trans)
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);

	lockdep_assert_held(&trans_pcie->reg_lock);

	/*
	 * Fool sparse by faking we acquiring the lock - sparse will
	 * track nic_access anyway.
	 */
	__acquire(&trans_pcie->reg_lock);

	iwl_trans_clear_bit(trans, CSR_GP_CNTRL,
			    CSR_GP_CNTRL_REG_FLAG_BZ_MAC_ACCESS_REQ);

	__release(nic_access);
	spin_unlock(&trans_pcie->reg_lock);
}

int iwl_trans_pcie_gen3_read_mem(struct iwl_trans *trans, u32 addr,
				 void *buf, int dwords)
{
#define IWL_MAX_HW_ERRS 5
	unsigned int num_consec_hw_errors = 0;
	int offs = 0;
	u32 *vals = buf;

	/* TODO: add support for Vlab (task=vlab) */

	while (offs < dwords) {
		/* limit the time we spin here under lock to 1/2s */
		unsigned long end = jiffies + HZ / 2;
		bool resched = false;

		if (iwl_trans_grab_nic_access(trans)) {
			iwl_write32(trans, HBUS_TARG_MEM_RADDR,
				    addr + 4 * offs);

			while (offs < dwords) {
				vals[offs] = iwl_read32(trans,
							HBUS_TARG_MEM_RDAT);

				if (iwl_trans_is_hw_error_value(vals[offs]))
					num_consec_hw_errors++;
				else
					num_consec_hw_errors = 0;

				if (num_consec_hw_errors >= IWL_MAX_HW_ERRS) {
					iwl_trans_release_nic_access(trans);
					return -EIO;
				}

				offs++;

				if (time_after(jiffies, end)) {
					resched = true;
					break;
				}
			}
			iwl_trans_release_nic_access(trans);

			if (resched)
				cond_resched();
		} else {
			return -EBUSY;
		}
	}

	return 0;
}

void iwl_pcie_gen3_op_mode_enter(struct iwl_trans *trans)
{
	IWL_ERR(trans, "%s NOT IMPLEMENTED\n", __func__);
}

void iwl_pcie_gen3_op_mode_leave(struct iwl_trans *trans)
{
	IWL_ERR(trans, "%s NOT IMPLEMENTED\n", __func__);
}

#ifdef CPTCFG_IWLWIFI_SIMULATION
struct request_fw_work {
	struct work_struct work;
	struct iwl_trans *trans;
	void (*cont)(const struct firmware *fw, void *context);
	void *context;
};

static void iwl_pcie_gen3_load_firmware_wk(struct work_struct *work)
{
	struct request_fw_work *wk =
		container_of(work, struct request_fw_work, work);
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(wk->trans);
	u32 image_size;
	void *fw_image, *vdata;
	struct firmware *fw;

	if (WARN(!wk->cont, "no callback function set\n"))
		return;

	/* This BAR is really magic ... */
	/* ... first, we read the size */
	image_size = readl(trans_pcie->sim_base);
	if (!image_size || image_size == ~0)
		goto finish;

	fw = kzalloc(sizeof(*fw), GFP_KERNEL);

	fw_image = kmalloc(image_size, GFP_KERNEL);
	if (!fw_image || !fw)
		goto free;

	vdata = vmalloc(image_size);
	if (!vdata)
		goto free;

	fw->data = vdata;
	fw->size = image_size;

	/*
	 * ... secondly, we memcpy the data from that place
	 * (the simulation knows what to give us according to the size we
	 * requested)
	 */
	memcpy_fromio(fw_image, trans_pcie->sim_base, image_size);

	/*
	 * fw_image needs to be contigious, so it'll be DMA capable,
	 * but release_firmware() will do vfree, so copy to virtual memory,
	 * and let the fw object have a pointer to it.
	 */
	memcpy(vdata, fw_image, image_size);

	kfree(fw_image);
	/* fw, and vdata memory release happens in the callback */
	wk->cont(fw, wk->context);
	kfree(wk);
	return;
free:
	kfree(fw);
	kfree(fw_image);
finish:
	wk->cont(NULL, wk->context);
	kfree(wk);
}

int iwl_pcie_gen3_request_firmware(struct iwl_trans *trans, void *context,
				   void (*cont)(const struct firmware *fw,
						void *context))
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);
	struct request_fw_work *wk;

	if (!trans_pcie->sim_base)
		return -ENOENT;

	wk = kzalloc(sizeof(*wk), GFP_KERNEL);

	if (!wk)
		return -ENOMEM;

	wk->trans = trans;
	wk->cont = cont;
	wk->context = context;
	INIT_WORK(&wk->work, iwl_pcie_gen3_load_firmware_wk);
	schedule_work(&wk->work);

	return 0;
}
#endif

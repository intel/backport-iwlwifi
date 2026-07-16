// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __iwl_trans_pcie_gen3_h__
#define __iwl_trans_pcie_gen3_h__

#include "iwl-trans.h"
#include "pcie/utils.h"
#include <linux/pci.h>
#include "interrupts.h"

/**
 * struct iwl_pcie_gen3 - Generation 3 PCIe transport specific data
 *
 * @trans: pointer to the generic transport
 * @napi_dev: netdev for NAPI registration
 * @pci_dev: basic pci-network driver stuff
 * @reg_lock: protect hw register access
 * @hw_base: PCI hardware address
 * @msix: msix related data
 */
struct iwl_pcie_gen3 {
	struct iwl_trans *trans;

	struct net_device *napi_dev;
	/* PCI bus related data */
	struct pci_dev *pci_dev;
	spinlock_t reg_lock;

	u8 __iomem *hw_base;

	struct iwl_msix msix;

#ifdef CPTCFG_IWLWIFI_SIMULATION
	/**
	 * @sim_base: simulation BAR pointer
	 */
	u8 __iomem *sim_base;
#endif
};

int iwl_pci_gen3_probe(struct pci_dev *pdev,
		       const struct pci_device_id *ent,
		       const struct iwl_mac_cfg *mac_cfg, u8 __iomem *hw_base,
		       u32 hw_rev);

void iwl_pcie_gen3_remove(struct iwl_trans *trans);

int iwl_pcie_gen3_start_hw(struct iwl_trans *trans);

int iwl_pcie_gen3_sw_reset(struct iwl_trans *trans, bool retake_ownership);

void iwl_pcie_gen3_op_mode_enter(struct iwl_trans *trans);

void iwl_pcie_gen3_op_mode_leave(struct iwl_trans *trans);

int iwl_pcie_gen3_activate_nic(struct iwl_trans *trans);

#ifdef CPTCFG_IWLWIFI_SIMULATION
int iwl_pcie_gen3_request_firmware(struct iwl_trans *trans, void *context,
				   void (*cont)(const struct firmware *fw,
						void *context));
#endif

static inline struct iwl_pcie_gen3 *
IWL_GET_PCIE_GEN3(struct iwl_trans *trans)
{
	return (void *)trans->trans_specific;
}

/* PCI registers */
#define PCI_CFG_RETRY_TIMEOUT	0x041

static inline void
iwl_trans_pcie_gen3_set_bits_mask(struct iwl_trans *trans, u32 reg,
				  u32 mask, u32 value)
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);

	spin_lock(&trans_pcie->reg_lock);
	_iwl_trans_set_bits_mask(trans, reg, mask, value);
	spin_unlock(&trans_pcie->reg_lock);
}

static inline void
iwl_trans_pcie_gen3_write8(struct iwl_trans *trans, u32 ofs, u8 val)
{
	writeb(val, IWL_GET_PCIE_GEN3(trans)->hw_base + ofs);
}

static inline void
iwl_trans_pcie_gen3_write32(struct iwl_trans *trans, u32 ofs, u32 val)
{
	writel(val, IWL_GET_PCIE_GEN3(trans)->hw_base + ofs);
}

static inline u32
iwl_trans_pcie_gen3_read32(struct iwl_trans *trans, u32 ofs)
{
	return readl(IWL_GET_PCIE_GEN3(trans)->hw_base + ofs);
}

#define IWL_PRPH_MASK 0x00FFFFFF

static inline u32
iwl_trans_pcie_gen3_read_prph(struct iwl_trans *trans, u32 reg)
{
	iwl_trans_pcie_gen3_write32(trans, HBUS_TARG_PRPH_RADDR,
				    ((reg & IWL_PRPH_MASK) | (3 << 24)));
	return iwl_trans_pcie_gen3_read32(trans, HBUS_TARG_PRPH_RDAT);
}

static inline void
iwl_trans_pcie_gen3_write_prph(struct iwl_trans *trans, u32 addr, u32 val)
{
	iwl_trans_pcie_gen3_write32(trans, HBUS_TARG_PRPH_WADDR,
				    ((addr & IWL_PRPH_MASK) | (3 << 24)));
	iwl_trans_pcie_gen3_write32(trans, HBUS_TARG_PRPH_WDAT, val);
}

static inline int
iwl_trans_pcie_gen3_read_config32(struct iwl_trans *trans, u32 ofs, u32 *val)
{
	return pci_read_config_dword(IWL_GET_PCIE_GEN3(trans)->pci_dev,
				     ofs, val);
}

bool iwl_trans_pcie_gen3_grab_nic_access(struct iwl_trans *trans);
void __releases(nic_access)
iwl_trans_pcie_gen3_release_nic_access(struct iwl_trans *trans);
int iwl_trans_pcie_gen3_read_mem(struct iwl_trans *trans, u32 addr,
				 void *buf, int dwords);

#endif /* __iwl_trans_pcie_gen3_h__ */

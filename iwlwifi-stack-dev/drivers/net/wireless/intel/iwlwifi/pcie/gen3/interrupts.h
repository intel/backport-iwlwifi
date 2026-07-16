// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#ifndef __iwl_trans_pcie_gen3_intrpts__
#define __iwl_trans_pcie_gen3_intrpts__

#include <iwl-trans.h>

/**
 * enum iwl_def_rxq_shared_irq_flags - level of sharing for default rxq's irq
 * @IWL_GEN3_SHARED_IRQ_DEFAULT_RXQ: irq serves the default rx queue.
 * @IWL_GEN3_SHARED_IRQ_NON_RX: irq serves non rx causes.
 * @IWL_GEN3_SHARED_IRQ_FIRST_RXQ: irq serves first RSS queue.
 */
enum iwl_def_rxq_shared_irq_flags {
	IWL_GEN3_SHARED_IRQ_DEFAULT_RXQ		= BIT(0),
	IWL_GEN3_SHARED_IRQ_NON_RX		= BIT(1),
	IWL_GEN3_SHARED_IRQ_FIRST_RXQ		= BIT(2),
};

int iwl_pcie_setup_msix(struct pci_dev *pdev,
			struct iwl_trans *trans,
			struct iwl_trans_info *info);
void iwl_pcie_gen3_sync_irqs(struct iwl_trans *trans);

/**
 * struct iwl_msix - MSIX related data
 * @is_enabled: true if managed to enable MSI-X
 * @entries: array of MSI-X entries
 * @shared_irq_mask: the type of causes shared with the default rxq's irq
 * @alloc_irqs: the number of irqs allocated by msix
 * @non_rx_irq: irq for non rx causes
 * @affinity_mask: IRQ affinity mask for each RX queue
 */
struct iwl_msix {
	bool is_enabled;
	struct msix_entry entries[IWL_MAX_RX_HW_QUEUES];
	u8 shared_irq_mask;
	u32 alloc_irqs;
	u32 non_rx_irq;
	cpumask_t affinity_mask[IWL_MAX_RX_HW_QUEUES];
};

#define DEFAULT_RXQ 0
#define FIRST_RXQ 1

#endif /* __iwl_trans_pcie_gen3_intrpts__ */

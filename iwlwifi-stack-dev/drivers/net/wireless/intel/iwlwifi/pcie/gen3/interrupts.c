// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Intel Corporation
 */

#include <linux/pci.h>

#include "interrupts.h"
#include "trans.h"

static int iwl_pcie_alloc_msix_irqs(struct pci_dev *pdev,
				    struct iwl_trans *trans,
				    struct iwl_trans_info *info)
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);
	int max_irqs, num_irqs;

	/* We want to allocate an rxq for each CPU plus a default queue (rxq 0).
	 * Every rxq should have a matching irq. Additionally, we reserve
	 * another irq for non rx interrupts.
	 */
	max_irqs = min_t(u32, num_online_cpus() + 2, IWL_MAX_RX_HW_QUEUES);
	for (int i = 0; i < max_irqs; i++)
		trans_pcie->msix.entries[i].entry = i;

	num_irqs = pci_enable_msix_range(pdev, trans_pcie->msix.entries,
					 MSIX_MIN_INTERRUPT_VECTORS,
					 max_irqs);
	if (num_irqs < 0) {
		IWL_DEBUG_ISR(trans,
			      "Failed to enable msi-x mode (ret %d).\n",
			      num_irqs);
		return -ENODEV;
	}

	IWL_DEBUG_ISR(trans,
		      "MSI-X enabled. %d irqs were allocated\n",
		      num_irqs);

	/* In case the OS provides fewer irqs than requested, different
	 * causes will share the default rxq's irq as follows:
	 * One irq less: non rx causes shared with default rxq.
	 * Two irqs less: non rx causes shared with default rxq and RSS #1.
	 * More than two irq: we will use fewer RSS queues.
	 */
	trans_pcie->msix.shared_irq_mask = IWL_GEN3_SHARED_IRQ_DEFAULT_RXQ;
	if (num_irqs == max_irqs) {
		info->num_rxqs = num_irqs - 1;
	} else if (num_irqs == max_irqs - 1) {
		info->num_rxqs = num_irqs;
		trans_pcie->msix.shared_irq_mask |= IWL_GEN3_SHARED_IRQ_NON_RX;
	} else {
		info->num_rxqs = num_irqs + 1;
		trans_pcie->msix.shared_irq_mask |= IWL_GEN3_SHARED_IRQ_NON_RX |
			IWL_GEN3_SHARED_IRQ_FIRST_RXQ;
	}

	/* If at least one of the irqs is shared, non rx irq is shared
	 * with the default rxq.
	 */
	trans_pcie->msix.non_rx_irq = (num_irqs == max_irqs) ? num_irqs - 1 :
		DEFAULT_RXQ;

	WARN_ON(info->num_rxqs > IWL_MAX_RX_HW_QUEUES);

	IWL_DEBUG_ISR(trans,
		      "MSI-X enabled. rx queues=%d, shared_irq_mask=0x%x\n",
		      info->num_rxqs, trans_pcie->msix.shared_irq_mask);

	trans_pcie->msix.is_enabled = true;
	trans_pcie->msix.alloc_irqs = num_irqs;
	return 0;
}

static irqreturn_t iwl_pcie_gen3_irq_rx_msix_handler(int irq, void *dev_id)
{
	/* TODO: task=rx*/
	return IRQ_NONE;
}

static irqreturn_t iwl_pcie_gen3_irq_msix_handler(int irq, void *dev_id)
{
	/* TODO: task=rx*/
	return IRQ_NONE;
}

static irqreturn_t iwl_pcie_gen3_msix_isr(int irq, void *data)
{
	return IRQ_WAKE_THREAD;
}

static void
iwl_pcie_gen3_irq_set_affinity(struct iwl_trans *trans,
			       struct iwl_trans_info *info)
{
#if defined(CONFIG_SMP)
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);
	unsigned int cpu;
	int cpu_index = 0;
	int ret;

	/* Iterate over rxqs' irqs (exclude default rxq unless it's irq is
	 * shared with the first rxq) and set their irq affinity
	 */
	for (int irq_iter = 0; irq_iter < trans_pcie->msix.alloc_irqs;
	     irq_iter++) {
		if (irq_iter == DEFAULT_RXQ &&
		    !(trans_pcie->msix.shared_irq_mask &
		      IWL_GEN3_SHARED_IRQ_FIRST_RXQ))
			continue;

		if (irq_iter == trans_pcie->msix.alloc_irqs - 1 &&
		    !(trans_pcie->msix.shared_irq_mask &
		      IWL_GEN3_SHARED_IRQ_NON_RX))
			break;

		/* cpumask_next receives the cpu prior to the place to search,
		 * start with -1
		 */
		cpu = cpumask_next(cpu_index - 1, cpu_online_mask);
		cpumask_set_cpu(cpu,
				&trans_pcie->msix.affinity_mask[irq_iter]);
		ret = irq_set_affinity_hint(trans_pcie->msix.entries[irq_iter].vector,
					    &trans_pcie->msix.affinity_mask[irq_iter]);
		if (ret)
			IWL_ERR(trans,
				"Failed to set affinity mask for IRQ %d\n",
				trans_pcie->msix.entries[irq_iter].vector);
		cpu_index++;
	}
#endif
}

static const char *
iwl_pcie_queue_name(struct device *dev,
		    struct iwl_pcie_gen3 *trans_pcie, int irq_num)
{
	int shared_rss_offset = trans_pcie->msix.shared_irq_mask &
		IWL_GEN3_SHARED_IRQ_FIRST_RXQ ? 1 : 0;

	if (irq_num == DEFAULT_RXQ &&
	    trans_pcie->msix.shared_irq_mask & ~IWL_GEN3_SHARED_IRQ_DEFAULT_RXQ)
		return DRV_NAME ":shared_IRQ";

	if (irq_num == DEFAULT_RXQ)
		return DRV_NAME ":default_queue";

	if (irq_num == trans_pcie->msix.non_rx_irq)
		return DRV_NAME ":exception";

	return devm_kasprintf(dev, GFP_KERNEL,
			      DRV_NAME  ":queue_%d",
			      irq_num + shared_rss_offset);
}

static int
iwl_gen3_register_handlers(struct pci_dev *pdev,
			   struct iwl_pcie_gen3 *trans_pcie)
{
	for (int i = 0; i < trans_pcie->msix.alloc_irqs; i++) {
		struct msix_entry *msix_entry;
		const char *qname = iwl_pcie_queue_name(&pdev->dev, trans_pcie,
							i);
		int ret;

		if (!qname)
			return -ENOMEM;

		msix_entry = &trans_pcie->msix.entries[i];
		ret = devm_request_threaded_irq(&pdev->dev,
						msix_entry->vector,
						iwl_pcie_gen3_msix_isr,
						(i == trans_pcie->msix.non_rx_irq) ?
						iwl_pcie_gen3_irq_msix_handler :
						iwl_pcie_gen3_irq_rx_msix_handler,
						IRQF_SHARED,
						qname,
						msix_entry);
		if (ret) {
			IWL_ERR(trans_pcie->trans,
				"Error registering IRQ %d handler\n", i);

			return ret;
		}
	}

	return 0;
}

int iwl_pcie_setup_msix(struct pci_dev *pdev,
			struct iwl_trans *trans,
			struct iwl_trans_info *info)
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);
	int ret;

	if (!iwlwifi_mod_params.disable_msix)
		return -EOPNOTSUPP;

	ret = iwl_pcie_alloc_msix_irqs(pdev, trans, info);
	if (ret)
		return ret;

	ret = iwl_gen3_register_handlers(pdev, trans_pcie);
	if (ret)
		return ret;

	iwl_pcie_gen3_irq_set_affinity(trans_pcie->trans, info);

	return 0;
}

void iwl_pcie_gen3_sync_irqs(struct iwl_trans *trans)
{
	struct iwl_pcie_gen3 *trans_pcie = IWL_GET_PCIE_GEN3(trans);

	if (!trans_pcie->msix.is_enabled)
		/* TODO: sync msi irq, task=msi*/
		return;

	for (int i = 0; i < trans_pcie->msix.alloc_irqs; i++)
		synchronize_irq(trans_pcie->msix.entries[i].vector);
}

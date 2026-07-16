static inline int pcim_request_all_regions(struct pci_dev *pdev, const char *name)
{
	/* NOTE: this only works with pcim_enable_device() on older kernels */
	int mask = 0;

	for (int i = 0; i < PCI_STD_NUM_BARS; i++) {
		if (!pci_resource_start(pdev, i))
			continue;
		if (!pci_resource_len(pdev, i))
			continue;
		mask |= BIT(i);
	}

	return pci_request_selected_regions(pdev, mask, name);
}

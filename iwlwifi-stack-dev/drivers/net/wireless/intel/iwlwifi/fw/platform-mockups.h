/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2021 Intel Corporation
 */
#ifndef __iwl_fw_platform_mockups__
#define __iwl_fw_platform_mockups__

#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/mod_devicetable.h>
#include <linux/dmi.h>
#include "acpi.h"
#include "iwl-modparams.h"

/* We're mocking ACPI, so define CONFIG_ACPI */
#ifndef CONFIG_ACPI
#define CONFIG_ACPI 1
#endif

/* And same for EFI */
#ifndef CONFIG_EFI
#define CONFIG_EFI 1
#else
#define IWL_HAVE_REAL_EFI 1
#endif

/* This macro's name was changed in v5.2. */
#ifndef ACPI_NAMESEG_SIZE
#define ACPI_NAMESEG_SIZE ACPI_NAME_SIZE
#endif

/* Maximum object nesting */
#define IWLWIFI_ACPI_MOCKUP_MAX_RECURSION 10
#define IWLWIFI_ACPI_MOCKUP_DSM_METHOD "_DSM"

/* special name for EFI variables in the file */
#define IWLWIFI_EFI_MOCKUP_ACPI_NAME "\x01" "EFI"

/* special name for DMI variables in the file */
#define IWLWIFI_DMI_MOCKUP_ACPI_NAME "\x01" "DMI"

struct iwl_fw_runtime;

struct mockup_object {
	char name[ACPI_NAMESEG_SIZE];
	__be32 len;
	u8 data[];
} __packed;

struct mockup_acpi_handle {
	struct list_head list;

	char name[ACPI_NAMESEG_SIZE + 1];
	u32 size;
	union acpi_object object;
};

struct mockup_acpi_dsm_key {
	__be32 guid32;
	__be16 guid16_1;
	__be16 guid16_2;
	u8 guid8[8];
	__be64 rev;
	__be64 func;
} __packed;

struct mockup_acpi_dsm_func {
	struct list_head list;

	struct {
		u32 guid32;
		u16 guid16_1;
		u16 guid16_2;
		u8 guid8[8];
	} __packed key;

	u64 rev;
	u64 func;

	union acpi_object object;
};

/*
 * mockup EFI vars are stored in the file with a special 'ACPI' name
 * (see IWLWIFI_EFI_MOCKUP_ACPI_NAME)
 */
struct mockup_efi_var {
	struct list_head list;

	struct {
		efi_char16_t VariableName[EFI_VAR_NAME_LEN / sizeof(efi_char16_t)];
		efi_guid_t   VendorGuid;
	} __packed key;

	unsigned int size;
	u8 data[];
};

/*
 * TODO: This is actually a void *, so we can assign a table of
 * methods/objects here.
 */
extern acpi_handle mockup_acpi_root_handle;

static inline acpi_handle _acpi_handle(struct device *dev)
{
	return (iwlwifi_mod_params.enable_acpi_mockups ?
		mockup_acpi_root_handle : ACPI_HANDLE(dev));
}

#undef ACPI_HANDLE
#define ACPI_HANDLE(dev) _acpi_handle(dev)

static inline void _acpi_free(void *p)
{
	if (iwlwifi_mod_params.enable_acpi_mockups)
		kfree(p);
	else
		ACPI_FREE(p);
}

#undef ACPI_FREE
#define ACPI_FREE(p) _acpi_free(p)

acpi_status _acpi_get_handle(acpi_handle parent, acpi_string pathname,
			     acpi_handle *ret_handle);
#undef acpi_get_handle
#define acpi_get_handle _acpi_get_handle

acpi_status _acpi_evaluate_object(acpi_handle object,
				  acpi_string pathname,
				  struct acpi_object_list *parameter_objects,
				  struct acpi_buffer *return_object_buffer);
#undef acpi_evaluate_object
#define acpi_evaluate_object _acpi_evaluate_object

union acpi_object *_acpi_evaluate_dsm(acpi_handle handle,
				      const guid_t *guid,
				      u64 rev, u64 func,
				      union acpi_object *argv4);
#undef acpi_evaluate_dsm
#define acpi_evaluate_dsm _acpi_evaluate_dsm

int _efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
		      unsigned long *size, void *data);
#define efivar_entry_get _efivar_entry_get

const char *_dmi_get_system_info(int field);
#define dmi_get_system_info _dmi_get_system_info

int _dmi_check_system(const struct dmi_system_id *list);
#define dmi_check_system _dmi_check_system

bool _dmi_match(enum dmi_field f, const char *str);
#define dmi_match _dmi_match

int iwl_platform_mockups_init(void);
void iwl_platform_mockups_free(void);
#endif /* __iwl_fw_platform_mockups__ */

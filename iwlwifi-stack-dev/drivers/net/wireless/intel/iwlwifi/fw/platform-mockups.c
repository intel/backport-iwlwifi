// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2021 Intel Corporation
 */

#include "iwl-drv.h"
#include "platform-mockups.h"
#include "acpi.h"
#include "fw/runtime.h"

/*
 * Define a dummy root handle, later we should make this point to the
 * list of handles we will introcude, so we can potentially support
 * multiple devices with different settings.
*/
acpi_handle mockup_acpi_root_handle = (void *)0x01020304;

static LIST_HEAD(mockup_acpi_table_list);
static LIST_HEAD(mockup_acpi_dsm_list);
static LIST_HEAD(mockup_efi_var_list);
static char *mockup_dmi_ident[DMI_STRING_MAX];

static acpi_status mockup_acpi_get_handle(acpi_handle parent,
					  acpi_string pathname,
					  acpi_handle *ret_handle)
{
	struct mockup_acpi_handle *entry;

	list_for_each_entry(entry, &mockup_acpi_table_list, list) {
		if (!strcmp(entry->name, pathname)) {
			*ret_handle = entry;
			return AE_OK;
		}
	}

	return AE_NOT_EXIST;
}

static acpi_status
mockup_acpi_evaluate_object(acpi_handle object,
			    acpi_string pathname,
			    struct acpi_object_list *parameter_objects,
			    struct acpi_buffer *return_object_buffer)
{
	struct mockup_acpi_handle *handle = object;

	/* we only support handles, not pathnames */
	if (!handle)
		return AE_BAD_PARAMETER;

	if (pathname)
		return AE_BAD_PARAMETER;

	return_object_buffer->length = handle->size;
	return_object_buffer->pointer = kmemdup(&handle->object, handle->size,
						GFP_KERNEL);
	if (!return_object_buffer->pointer)
		return AE_NO_MEMORY;

	return AE_OK;
}

static int iwl_acpi_mockup_parse_object(union acpi_object *object,
					const u8 *data, int len, int level);

static void iwl_acpi_mockup_free_package(union acpi_object *obj)
{
	int i;

	/* search for packages to free them recursively */
	for (i = 0; i < obj->package.count; i++)
		if (obj->package.elements[i].type == ACPI_TYPE_PACKAGE)
			iwl_acpi_mockup_free_package(&obj->package.elements[i]);

	/* now we can free all elements */
	kfree(obj->package.elements);
}

static int iwl_acpi_mockup_parse_package(union acpi_object *object,
					 const u8 *data, int len, int level)
{
	int i, used = 0;

	if (len < sizeof(__be32))
		return -EINVAL;

	object->package.count = get_unaligned_be32(data);

	used += sizeof(__be32);
	data += sizeof(__be32);
	len -= sizeof(__be32);

	object->package.elements = kcalloc(object->package.count,
					   sizeof(object->package.elements[0]),
					   GFP_KERNEL);
	if (!object->package.elements)
		return -ENOMEM;

	for (i = 0; i < object->package.count; i++) {
		int ret;

		ret = iwl_acpi_mockup_parse_object(&object->package.elements[i],
						   data, len, level + 1);
		if (ret < 0) {
			/*
			 * Free the package we're currently handling
			 * to include elements that were already
			 * allocated.
			 */
			iwl_acpi_mockup_free_package(object);

			return ret;
		}

		used += ret;
		data += ret;
		len -= ret;
	}

	return used;
}

static int iwl_acpi_mockup_parse_integer(union acpi_object *object,
					 const u8 *data, int len)
{
	if (len < sizeof(object->integer.value))
		return -EINVAL;

	object->integer.value = get_unaligned_be64(data);

	return sizeof(__be64);
}

static int iwl_acpi_mockup_parse_object(union acpi_object *object,
					const u8 *data, int len, int level)
{
	int ret, used = 0;

	if (level >= IWLWIFI_ACPI_MOCKUP_MAX_RECURSION)
		return -ELOOP;

	if (len < 1)
		return -EINVAL;

	object->type = *(const u8 *)data;

	used += sizeof(u8);
	data += sizeof(u8);
	len -= sizeof(u8);

	switch (object->type) {
	case ACPI_TYPE_INTEGER:
		ret = iwl_acpi_mockup_parse_integer(object, data, len);
		if (ret < 0)
			return ret;

		used += ret;
		break;
	case ACPI_TYPE_STRING:
		break;
	case ACPI_TYPE_BUFFER:
		break;
	case ACPI_TYPE_PACKAGE:
		ret = iwl_acpi_mockup_parse_package(object, data, len, level);
		if (ret < 0)
			return ret;

		used += ret;
		break;
	default:
		break;
	}

	return used;
}

static int iwl_acpi_mockup_parse_dsm(const u8 *data, int len)
{
	struct mockup_acpi_dsm_func *func;
	const struct mockup_acpi_dsm_key *key;
	int used = 0;

	while (len >= sizeof(*key)) {
		int ret;

		func = kzalloc(sizeof(*func), GFP_KERNEL);
		if (!func)
			return -ENOMEM;

		key = (const void *)data;

		func->key.guid32 = get_unaligned_be32(&key->guid32);
		func->key.guid16_1 = get_unaligned_be16(&key->guid16_1);
		func->key.guid16_2 = get_unaligned_be16(&key->guid16_2);
		memcpy(func->key.guid8, key->guid8, sizeof(func->key.guid8));

		func->rev = get_unaligned_be64(&key->rev);

		func->func = get_unaligned_be64(&key->func);

		used += sizeof(*key);
		data += sizeof(*key);
		len -= sizeof(*key);

		ret = iwl_acpi_mockup_parse_object(&func->object, data, len, 0);
		if (ret < 0) {
			kfree(func);

			return ret;
		}

		list_add(&func->list, &mockup_acpi_dsm_list);

		used += ret;
		data += ret;
		len -= ret;
	}

	if (len)
		return -EINVAL;

	return used;
}

int iwl_platform_mockups_init(void)
{
	const struct firmware *tables_file;
	const struct mockup_object *obj;
	int ret, len;

	if (!iwlwifi_mod_params.enable_acpi_mockups &&
	    !iwlwifi_mod_params.enable_efi_mockups &&
	    !iwlwifi_mod_params.enable_dmi_mockups)
		return 0;

	ret = request_firmware(&tables_file, "iwlwifi-platform.dat", NULL);
	if (ret)
		goto out;

	len = tables_file->size;
	obj = (const void *)tables_file->data;

	while (len >= sizeof(*obj)) {
		struct mockup_acpi_handle *new_method;
		u32 object_len;

		object_len = be32_to_cpu(obj->len);

		if (len < sizeof(*obj) + object_len) {
			ret = -EINVAL;
			goto free;
		}
		if (!memcmp(obj->name, IWLWIFI_DMI_MOCKUP_ACPI_NAME,
			    ACPI_NAMESEG_SIZE)) {
			u8 field;

			/* at least one byte for the index is needed */
			if (object_len < sizeof(field)) {
				ret = -EINVAL;
				goto free;
			}

			field =  *obj->data;

			mockup_dmi_ident[field] =
				kstrndup(obj->data + sizeof(field),
					 object_len - sizeof(field),
					 GFP_KERNEL);

			ret = object_len;
		} else if (!memcmp(obj->name, IWLWIFI_EFI_MOCKUP_ACPI_NAME,
				   ACPI_NAMESEG_SIZE)) {
			struct mockup_efi_var *var;

			if (object_len < sizeof(var->key)) {
				ret = -EINVAL;
				goto free;
			}

			var = kzalloc(sizeof(*var) + object_len, GFP_KERNEL);
			if (!var) {
				ret = -ENOMEM;
				goto free;
			}

			memcpy(&var->key, obj->data, sizeof(var->key));
			var->size = object_len - sizeof(var->key);
			memcpy(var->data, obj->data + sizeof(var->key),
			       var->size);
			list_add(&var->list, &mockup_efi_var_list);
			ret = object_len;
		} else if (!memcmp(obj->name, IWLWIFI_ACPI_MOCKUP_DSM_METHOD,
				   ACPI_NAMESEG_SIZE)) {
			ret = iwl_acpi_mockup_parse_dsm(obj->data, object_len);
		} else {
			new_method = kzalloc(sizeof(*new_method), GFP_KERNEL);
			if (!new_method) {
				ret = -ENOMEM;
				goto free;
			}

			memcpy(new_method->name, obj->name, sizeof(obj->name));

			ret = iwl_acpi_mockup_parse_object(&new_method->object,
							   obj->data,
							   object_len, 0);

			/* add even if it failed, to free it later */
			list_add(&new_method->list, &mockup_acpi_table_list);
			new_method->size = object_len;
		}

		if (ret < 0)
			goto free;

		if (ret != object_len) {
			ret = -EINVAL;
			goto free;
		}

		obj = (const void *)((const char *)obj +
				      sizeof(*obj) + object_len);
		len -= sizeof(*obj) + object_len;
	};

	if (len) {
		ret = -EINVAL;
		goto free;
	}

	ret = 0;
	goto release;

free:
	iwl_platform_mockups_free();
release:
	release_firmware(tables_file);
out:
	return ret;
}

void iwl_platform_mockups_free(void)
{
	struct mockup_acpi_handle *entry, *tmp;
	struct mockup_acpi_dsm_func *dsm_entry, *tmp2;
	int i;

	if (!iwlwifi_mod_params.enable_acpi_mockups &&
	    !iwlwifi_mod_params.enable_efi_mockups &&
	    !iwlwifi_mod_params.enable_dmi_mockups)
		return;

	list_for_each_entry_safe(entry, tmp, &mockup_acpi_table_list, list) {
		/* free packages separately */
		if (entry->object.type == ACPI_TYPE_PACKAGE)
			iwl_acpi_mockup_free_package(&entry->object);

		list_del(&entry->list);
		kfree(entry);
	}

	list_for_each_entry_safe(dsm_entry, tmp2, &mockup_acpi_dsm_list, list) {
		/* free packages separately */
		if (dsm_entry->object.type == ACPI_TYPE_PACKAGE)
			iwl_acpi_mockup_free_package(&dsm_entry->object);

		list_del(&dsm_entry->list);
		kfree(dsm_entry);
	}

	for (i = 0; i < ARRAY_SIZE(mockup_dmi_ident); i++)
		kfree(mockup_dmi_ident[i]);
}

static union acpi_object *mockup_acpi_evaluate_dsm(acpi_handle root,
						   const guid_t *guid,
						   u64 rev, u64 func,
						   union acpi_object *argv4)
{
	struct mockup_acpi_dsm_func *entry;

	list_for_each_entry(entry, &mockup_acpi_dsm_list, list) {
		if (!memcmp(guid, &entry->key, 16) &&
		    entry->rev == rev &&
		    entry->func == func) {
			union acpi_object *copy;

			copy = kmemdup(&entry->object, sizeof(entry->object),
				       GFP_KERNEL);
			if (!copy)
				return ERR_PTR(-ENOMEM);

			return copy;
		}
	}

	return NULL;
}

#undef acpi_get_handle
acpi_status _acpi_get_handle(acpi_handle parent, acpi_string pathname,
			     acpi_handle *ret_handle)
{
	return iwlwifi_mod_params.enable_acpi_mockups ?
		mockup_acpi_get_handle(parent, pathname, ret_handle) :
		acpi_get_handle(parent, pathname, ret_handle);
}

#undef acpi_evaluate_object
acpi_status _acpi_evaluate_object(acpi_handle object,
				  acpi_string pathname,
				  struct acpi_object_list *parameter_objects,
				  struct acpi_buffer *return_object_buffer)
{
	return iwlwifi_mod_params.enable_acpi_mockups ?
		mockup_acpi_evaluate_object(object, pathname, parameter_objects,
					    return_object_buffer) :
		acpi_evaluate_object(object, pathname, parameter_objects,
				     return_object_buffer);
}

#undef acpi_evaluate_dsm
union acpi_object *_acpi_evaluate_dsm(acpi_handle handle,
				      const guid_t *guid,
				      u64 rev, u64 func,
				      union acpi_object *argv4)
{
	return iwlwifi_mod_params.enable_acpi_mockups ?
		mockup_acpi_evaluate_dsm(handle, guid, rev, func, argv4) :
		acpi_evaluate_dsm(handle, guid, rev, func, argv4);
}

static int mockup_efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
				   unsigned long *size, void *data)
{
	struct mockup_efi_var *var;

	/* for the memcmp to work correctly */
	BUILD_BUG_ON(offsetof(struct efi_variable, VariableName) != 0);
	BUILD_BUG_ON(offsetofend(struct efi_variable, VariableName) !=
		     offsetof(struct efi_variable, VendorGuid));
	BUILD_BUG_ON(offsetofend(struct efi_variable, VendorGuid) !=
		     sizeof(var->key));

	list_for_each_entry(var, &mockup_efi_var_list, list) {
		if (!memcmp(&var->key, &entry->var, sizeof(var->key))) {
			*size = var->size;
			memcpy(data, var->data, var->size);
			return 0;
		}
	}

	return -ENOENT;
}

int _efivar_entry_get(struct efivar_entry *entry, u32 *attributes,
		      unsigned long *size, void *data)
{
	if (iwlwifi_mod_params.enable_efi_mockups)
		return mockup_efivar_entry_get(entry, attributes, size, data);
#ifdef IWL_HAVE_REAL_EFI
/* we need the original efivar_entry_get here */
#undef efivar_entry_get
	return efivar_entry_get(entry, attributes, size, data);
#else
	return -ENOENT;
#endif
}

bool _dmi_match(enum dmi_field f, const char *str)
{
	const char *info = dmi_get_system_info(f);

	if (!info || !str)
		return info == str;

	return !strcmp(info, str);
}
IWL_EXPORT_SYMBOL(_dmi_match);

static const char *mockup_dmi_get_system_info(int field)
{
	return mockup_dmi_ident[field];
}

#undef dmi_get_system_info
const char *_dmi_get_system_info(int field)
{
	return iwlwifi_mod_params.enable_dmi_mockups ?
		mockup_dmi_get_system_info(field) :
		dmi_get_system_info(field);
}
IWL_EXPORT_SYMBOL(_dmi_get_system_info);

static bool mockups_dmi_is_end_of_table(const struct dmi_system_id *dmi)
{
	return dmi->matches[0].slot == DMI_NONE;
}

static bool mockups_dmi_matches(const struct dmi_system_id *dmi)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dmi->matches); i++) {
		int s = dmi->matches[i].slot;

		if (s == DMI_NONE)
			break;
		/* this part don't have a mockup yet */
		if (WARN_ON(s == DMI_OEM_STRING)) {
			continue;
		} else if (mockup_dmi_ident[s]) {
			if (dmi->matches[i].exact_match) {
				if (!strcmp(mockup_dmi_ident[s],
					    dmi->matches[i].substr))
					continue;
			} else {
				if (strstr(mockup_dmi_ident[s],
					   dmi->matches[i].substr))
					continue;
			}
		}

		/* no match */
		return false;
	}
	return true;
}

static int mockup_dmi_check_system(const struct dmi_system_id *list)
{
	int count = 0;
	const struct dmi_system_id *d;

	for (d = list; !mockups_dmi_is_end_of_table(d); d++)
		if (mockups_dmi_matches(d)) {
			count++;
			if (d->callback && d->callback(d))
				break;
		}

	return count;
}

#undef dmi_check_system
int _dmi_check_system(const struct dmi_system_id *list)
{
	return iwlwifi_mod_params.enable_dmi_mockups ?
		mockup_dmi_check_system(list) :
		dmi_check_system(list);
}
IWL_EXPORT_SYMBOL(_dmi_check_system);

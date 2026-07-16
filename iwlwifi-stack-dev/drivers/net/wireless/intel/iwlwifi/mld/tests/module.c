// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * This is just module boilerplate for the iwlmld kunit module.
 *
 * Copyright (C) 2024 Intel Corporation
 */
#include <linux/module.h>

#if LINUX_VERSION_IS_LESS(6,13,0)
MODULE_IMPORT_NS(IWLWIFI);
#else
MODULE_IMPORT_NS("IWLWIFI");
#endif /* LINUX_VERSION_IS_LESS(6,13,0) */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kunit tests for iwlmld");

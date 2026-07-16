/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2025 Intel Corporation
 */
#ifndef __BP_KUNIT_STATIC_STUB_H
#define __BP_KUNIT_STATIC_STUB_H
#include <linux/version.h>

#if LINUX_VERSION_IS_LESS(6,3,0) || \
	(LINUX_VERSION_IS_LESS(6,6,0) && !IS_ENABLED(CONFIG_KUNIT))
#define KUNIT_STATIC_STUB_REDIRECT(real_fn_name, args...) do {} while (0)
#else
#include_next <kunit/static_stub.h>
#endif /* x < 6.3.0 or || (x < 6.6.0 || CONFIG_KUNIT disabled) */

#endif /* __BP_KUNIT_STATIC_STUB_H */

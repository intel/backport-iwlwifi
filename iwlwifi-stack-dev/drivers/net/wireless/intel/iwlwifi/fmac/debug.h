/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2016 Intel Deutschland GmbH
 */
#ifndef __DEBUG_H__
#define __DEBUG_H__

#define pr_fmt(fmt) "iwlfmac: "fmt

#include "fmac.h"

#define vif_info(vif, fmt, ...)	\
do {									\
	pr_info("%s: " fmt,						\
		(vif)->wdev.netdev ?					\
		(vif)->wdev.netdev->name : "no-netdev", ##__VA_ARGS__);	\
} while (0)

#endif /* __DEBUG_H__ */

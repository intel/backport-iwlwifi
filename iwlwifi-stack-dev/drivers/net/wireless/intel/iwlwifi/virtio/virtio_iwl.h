/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2019-2020 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/
#ifndef __VIRTIO_IWL_DEV
#define __VIRTIO_IWL_DEV
/* TODO: register this in a common place */
#define VIRTIO_ID_IWL 1000

/* TODO: not sure we need at all features */
#define VIRTIO_IWL_F_ID BIT(0)

enum virtio_iwl_device_op_mode {
	VRIRTIO_IWL_MVM,
	VRIRTIO_IWL_FMAC,
};

struct virtio_iwl_config {
	/* device ID */
	__le16 id;

	/* device op mode fmac/mvm */
	u8 opmode;

	u8 reserved;
} __packed;

struct virtio_iwl_fw_image {
	__le32 size;
	u8 data[0];
} __packed;

#define VIRTIO_IWL_S_LEN 4
enum virtio_iwl_s_status {
	VIRTIO_IWL_S_OK,
	VIRTIO_IWL_S_UNSUPP,
};

/* direction of the message
 * IN:1 OUT:0
 */
#define VIRTIO_IWL_F_DIR_MASK BIT(0)
#define VIRTIO_IWL_F_DIR_IN VIRTIO_IWL_F_DIR_MASK
#define VIRTIO_IWL_NR_SGS 3

enum virtio_iwl_events {
	VIRTIO_IWL_E_HW_START,
	VIRTIO_IWL_E_FW_START,
	VIRTIO_IWL_E_STOP_DEVICE,
	VIRTIO_IWL_E_GET_FW,
	VIRTIO_IWL_E_GET_FW_SIZE,
	VIRTIO_IWL_E_CONST_SIZE,
	VIRTIO_IWL_E_PRPH,
	VIRTIO_IWL_E_MEM,
	VIRTIO_IWL_E_SET_PMI,
};

enum virtio_iwl_queus {
	VIRTIO_IWL_Q_CONTROL_I = 0,
	VIRTIO_IWL_Q_CONTROL_O = 1,
	VIRTIO_IWL_Q_DEF_RX_I = 2,
	VIRTIO_IWL_Q_HCMD_O = 3,
	VIRTIO_IWL_Q_MAX,
};

/*
 * A message hdr (first sg always) that's passed between the
 * Host and the Guest for control
 */
struct virtio_iwl_control_hdr {
	__le32 event;	/* The kind of control event (see below) */
	__le32 flags;	/* direction of the message r/w */
	__le32 value;	/* used for address of r/w memory */
	__le32 len;	/* the len of valid data in the next sg */
};

#endif /* __VIRTIO_IWL_DEV */

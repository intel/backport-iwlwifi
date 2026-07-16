/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2024-2025 Intel Corporation
 */
#ifndef __IWL_SMART_TESTER_H__
#define __IWL_SMART_TESTER_H__

/*
 * Production uCode interface for bidirectional communication ("Smart Tester").
 *
 * Smart Tester serves as dedicated driver<->firmware interface used only in
 * production uCode replacing the standard hcmd/notif mechanisem of the
 * operational/regular uCode. To utilize this interface, the firmware
 * sets up a shared memory area (within HW SMEM) for read/write operations
 * in three distinct buffers:
 *
 * +---------------------------+  Size
 * | Command buffer (cmd)      |  around ~1KB (iwl_smart_tester_addr.cmd_size)
 * | +-----------------------+ |
 * | | TESTER_COMMAND_S      | |
 * | +-----------------------+ |
 * +---------------------------+
 * | Response buffer (rsp)     |  around ~1KB (iwl_smart_tester_addr.rsp_size)
 * | +-----------------------+ |
 * | | TESTER_RSP_NOTIF_S    | |
 * | +-----------------------+ |
 * +---------------------------+
 * | Error buffer (err)        |  around ~2KB (iwl_smart_tester_addr.err_size)
 * | +-----------------------+ |
 * | | TESTER_ERROR_S        | |
 * | +-----------------------+ |
 * +---------------------------+
 *
 * The information of addresses/sizes is parsed from
 * @IWL_UCODE_TLV_SMART_TESTER_ADDR.
 *
 * The driver populates the command buffer and notifies the device by
 * generating an interrupt through the UREG doorbell. There is no interrupt
 * in the reverse direction; the driver waits for a designated time, as
 * specified in @IWL_UCODE_TLV_SMART_TESTER_CMD_TIMEOUT, and then verifies
 * the presence of a response. If the response buffer is invalid (i.e., the
 * is_valid dword != SMART_TESTER_BUF_IS_VALID, or the id dword does not
 * match the command id), the driver should initiate the error flow.
 *
 * During the initialization flow, the driver refrains from sending any
 * commands. Instead, it sets up the context info and kick the device as usual,
 * subsequently waiting for the init complete response.
 */

/**
 * enum iwl_smart_tester_cmds - smart tester commands
 */
enum iwl_smart_tester_cmds {
	/**
	 * @SMART_TESTER_DUMMY_CMD:
	 * not in use
	 */
	SMART_TESTER_DUMMY_CMD = 0,

	/**
	 * @SMART_TESTER_INIT_CONFIG_CMD:
	 * host driver is not expected to send this command, but needs
	 * to wait for init complete (equivalent to "alive")
	 */
	SMART_TESTER_INIT_CONFIG_CMD = 1,
} /* SMART_TESTER_COMMANDS_ID_E */;

#define SMART_TESTER_BUF_IS_VALID	1

/**
 * struct iwl_smart_tester_header - Header format of the common smart tester
 * HW SMEM buffers
 *
 * @is_valid: Indicates whether the buffer is valid
 * @length: The buffer length (in dwords)
 * @ver_id: Version (currently set to 1)
 */
struct iwl_smart_tester_header {
	__le32 is_valid;
	__le32 length;
	__le32 ver_id;
} __packed; /* TESTER_HEADER_S */

/**
 * struct iwl_smart_tester_cmd_rsp - Command/Response buffer in the HW SMEM
 *
 * @hdr: Smart tester buffer header
 * @id: Command/Response id
 * @data: Command/Response data
 */
struct iwl_smart_tester_cmd_rsp {
	struct iwl_smart_tester_header hdr;
	__le32 id;
	__le32 data[];
} __packed; /* TESTER_COMMAND_S, TESTER_RSP_NOTIF_S */

/**
 * struct iwl_smart_tester_err - Error buffer in the HW SMEM
 *
 * @hdr: Smart tester buffer header
 * @err_id: Error id
 * @data: Error data
 */
struct iwl_smart_tester_err {
	struct iwl_smart_tester_header hdr;
	__le32 err_id;
	__le32 data[];
} __packed; /* TESTER_ERROR_S */

/**
 * struct iwl_smart_tester_addr - HW SMEM interface size/addresses
 *
 * Dedicated area in HW_SMEM for bidirectional communication.
 *
 * @cmd_addr: host command buffer base address
 * @cmd_size: host command buffer size in bytes
 * @rsp_addr: firmware response buffer base address
 * @rsp_size: firmware response buffer size in bytes
 * @err_addr: firmware error buffer base address
 * @err_size: firmware error buffer size in bytes
 */
struct iwl_smart_tester_addr {
	__le32 cmd_addr;
	__le32 cmd_size;
	__le32 rsp_addr;
	__le32 rsp_size;
	__le32 err_addr;
	__le32 err_size;
} __packed; /* FW_TLV_SMART_TESTER_ADDR_S */

/**
 * struct iwl_smart_tester_cmd_timeout_pair - Pairs of [cmd_id, timeout]
 *
 * Specifies for each command id, the duration to wait before checking the
 * response. This information is prased from
 * @FW_TLV_TYPE_SMART_TESTER_CMD_TIMEOUT.
 *
 * @cmd_id: cmd id
 * @timeout: timeout in msec
 */
struct iwl_smart_tester_cmd_timeout_pair {
	__le16 cmd_id;
	__le16 timeout;
} __packed; /* FW_TLV_SMART_TESTER_CMD_TIMEOUT_DATA_S */

#endif /* __IWL_SMART_TESTER_H__ */

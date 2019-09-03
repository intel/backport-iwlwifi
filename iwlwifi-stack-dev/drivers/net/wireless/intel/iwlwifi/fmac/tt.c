/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 Intel Corporation
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
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <linuxwifi@intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 * BSD LICENSE
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
#include <linux/sort.h>

#include "fmac.h"

#define IWL_FMAC_CTKILL_DURATION 5

/* budget in mWatt */
static const u32 iwl_fmac_cdev_budgets[] = {
	2000,	/* cooling state 0 */
	1800,	/* cooling state 1 */
	1600,	/* cooling state 2 */
	1400,	/* cooling state 3 */
	1200,	/* cooling state 4 */
	1000,	/* cooling state 5 */
	900,	/* cooling state 6 */
	800,	/* cooling state 7 */
	700,	/* cooling state 8 */
	650,	/* cooling state 9 */
	600,	/* cooling state 10 */
	550,	/* cooling state 11 */
	500,	/* cooling state 12 */
	450,	/* cooling state 13 */
	400,	/* cooling state 14 */
	350,	/* cooling state 15 */
	300,	/* cooling state 16 */
	250,	/* cooling state 17 */
	200,	/* cooling state 18 */
	150,	/* cooling state 19 */
};

int iwl_fmac_ctdp_command(struct iwl_fmac *fmac, u32 op, u32 state)
{
	struct iwl_mvm_ctdp_cmd cmd = {
		.operation = cpu_to_le32(op),
		.budget = cpu_to_le32(iwl_fmac_cdev_budgets[state]),
		.window_size = 0,
	};
	int ret;
	u32 status;

	lockdep_assert_held(&fmac->mutex);

	ret = iwl_fmac_send_cmd_pdu_status(fmac, WIDE_ID(PHY_OPS_GROUP,
							 CTDP_CONFIG_CMD),
					   sizeof(cmd), &cmd, &status);

	if (ret) {
		IWL_ERR(fmac, "cTDP command failed (err=%d)\n", ret);
		return ret;
	}

	switch (op) {
	case CTDP_CMD_OPERATION_START:
#ifdef CONFIG_THERMAL
		fmac->cooling_dev.cur_state = state;
#endif /* CONFIG_THERMAL */
		break;
	case CTDP_CMD_OPERATION_REPORT:
		IWL_DEBUG_TEMP(fmac, "cTDP avg energy in mWatt = %d\n", status);
		/* when the function is called with CTDP_CMD_OPERATION_REPORT
		 * option the function should return the average budget value
		 * that is received from the FW.
		 * The budget can't be less or equal to 0, so it's possible
		 * to distinguish between error values and budgets.
		 */
		return status;
	case CTDP_CMD_OPERATION_STOP:
		IWL_DEBUG_TEMP(fmac, "cTDP stopped successfully\n");
		break;
	}

	return 0;
}

#define IWL_FMAC_TEMP_NOTIF_WAIT_TIMEOUT	HZ

static int iwl_fmac_get_temp_cmd(struct iwl_fmac *fmac)
{
	struct iwl_ext_dts_measurement_cmd extcmd = {
		.control_mode = cpu_to_le32(DTS_AUTOMATIC),
	};
	u32 cmdid;

	cmdid = iwl_cmd_id(CMD_DTS_MEASUREMENT_TRIGGER_WIDE,
			   PHY_OPS_GROUP, 0);

	return iwl_fmac_send_cmd_pdu(fmac, cmdid, 0, sizeof(extcmd), &extcmd);
}

static int iwl_fmac_temp_notif_parse(struct iwl_fmac *fmac,
				     struct iwl_rx_packet *pkt)
{
	struct iwl_dts_measurement_notif_v2 *notif_v2;
	int len = iwl_rx_packet_payload_len(pkt);
	int temp;

	if (WARN_ON_ONCE(len < sizeof(*notif_v2))) {
		IWL_ERR(fmac, "Invalid DTS_MEASUREMENT_NOTIFICATION\n");
		return -EINVAL;
	}

	notif_v2 = (void *)pkt->data;

	temp = le32_to_cpu(notif_v2->temp);

	/* shouldn't be negative, but since it's s32, make sure it isn't */
	if (WARN_ON_ONCE(temp < 0))
		temp = 0;

	IWL_DEBUG_TEMP(fmac, "DTS_MEASUREMENT_NOTIFICATION - %d\n", temp);

	return temp;
}

static bool iwl_fmac_temp_notif_wait(struct iwl_notif_wait_data *notif_wait,
				     struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_fmac *fmac =
		container_of(notif_wait, struct iwl_fmac, notif_wait);
	int *temp = data;
	int ret;

	ret = iwl_fmac_temp_notif_parse(fmac, pkt);
	if (ret < 0)
		return true;

	*temp = ret;

	return true;
}

int iwl_fmac_get_temp(struct iwl_fmac *fmac, s32 *temp)
{
	struct iwl_notification_wait wait_temp_notif;
	static u16 temp_notif[] = { WIDE_ID(PHY_OPS_GROUP,
					    DTS_MEASUREMENT_NOTIF_WIDE) };
	int ret;

	lockdep_assert_held(&fmac->mutex);

	iwl_init_notification_wait(&fmac->notif_wait, &wait_temp_notif,
				   temp_notif, ARRAY_SIZE(temp_notif),
				   iwl_fmac_temp_notif_wait, temp);

	ret = iwl_fmac_get_temp_cmd(fmac);
	if (ret) {
		IWL_ERR(fmac, "Failed to get the temperature (err=%d)\n", ret);
		iwl_remove_notification(&fmac->notif_wait, &wait_temp_notif);
		return ret;
	}

	ret = iwl_wait_notification(&fmac->notif_wait, &wait_temp_notif,
				    IWL_FMAC_TEMP_NOTIF_WAIT_TIMEOUT);
	if (ret)
		IWL_ERR(fmac, "Getting the temperature timed out\n");

	return ret;
}

#ifdef CONFIG_THERMAL
static int compare_temps(const void *a, const void *b)
{
	return ((s16)le16_to_cpu(*(__le16 *)a) -
		(s16)le16_to_cpu(*(__le16 *)b));
}

static int iwl_fmac_send_temp_report_ths_cmd(struct iwl_fmac *fmac)
{
	struct temp_report_ths_cmd cmd = {0};
	int ret, i, j, idx = 0;

	lockdep_assert_held(&fmac->mutex);

	if (!fmac->tz_device.tzone)
		return -EINVAL;

	/* The driver holds array of temperature trips that are unsorted
	 * and uncompressed, the FW should get it compressed and sorted
	 */

	/* compress temp_trips to cmd array, remove uninitialized values*/
	for (i = 0; i < IWL_MAX_DTS_TRIPS; i++) {
		if (fmac->tz_device.temp_trips[i] != S16_MIN) {
			cmd.thresholds[idx++] =
				cpu_to_le16(fmac->tz_device.temp_trips[i]);
		}
	}
	cmd.num_temps = cpu_to_le32(idx);

	if (!idx)
		goto send;

	/*sort cmd array*/
	sort(cmd.thresholds, idx, sizeof(s16), compare_temps, NULL);

	/* we should save the indexes of trips because we sort
	 * and compress the orginal array
	 */
	for (i = 0; i < idx; i++) {
		for (j = 0; j < IWL_MAX_DTS_TRIPS; j++) {
			if (le16_to_cpu(cmd.thresholds[i]) ==
				fmac->tz_device.temp_trips[j])
				fmac->tz_device.fw_trips_index[i] = j;
		}
	}

send:
	ret = iwl_fmac_send_cmd_pdu(fmac,
				    WIDE_ID(PHY_OPS_GROUP,
					    TEMP_REPORTING_THRESHOLDS_CMD),
				    0, sizeof(cmd), &cmd);
	if (ret)
		IWL_ERR(fmac, "TEMP_REPORT_THS_CMD command failed (err=%d)\n",
			ret);

	return ret;
}

static int iwl_fmac_tzone_get_temp(struct thermal_zone_device *device,
				   int *temperature)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)device->devdata;
	int ret;
	int temp;

	mutex_lock(&fmac->mutex);

	if (!iwl_fmac_firmware_running(fmac) ||
	    fmac->fwrt.cur_fw_img != IWL_UCODE_REGULAR) {
		ret = -EIO;
		goto out;
	}

	ret = iwl_fmac_get_temp(fmac, &temp);
	if (ret)
		goto out;

	*temperature = temp * 1000;

out:
	mutex_unlock(&fmac->mutex);
	return ret;
}

static int iwl_fmac_tzone_get_trip_temp(struct thermal_zone_device *device,
					int trip, int *temp)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)device->devdata;

	if (trip < 0 || trip >= IWL_MAX_DTS_TRIPS)
		return -EINVAL;

	*temp = fmac->tz_device.temp_trips[trip] * 1000;

	return 0;
}

static int iwl_fmac_tzone_get_trip_type(struct thermal_zone_device *device,
					int trip, enum thermal_trip_type *type)
{
	if (trip < 0 || trip >= IWL_MAX_DTS_TRIPS)
		return -EINVAL;

	*type = THERMAL_TRIP_PASSIVE;

	return 0;
}

static int iwl_fmac_tzone_set_trip_temp(struct thermal_zone_device *device,
					int trip, int temp)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)device->devdata;
	struct iwl_fmac_thermal_device *tzone;
	int i, ret;
	s16 temperature;

	mutex_lock(&fmac->mutex);

	if (!iwl_fmac_firmware_running(fmac) ||
	    fmac->fwrt.cur_fw_img != IWL_UCODE_REGULAR) {
		ret = -EIO;
		goto out;
	}

	if (trip < 0 || trip >= IWL_MAX_DTS_TRIPS) {
		ret = -EINVAL;
		goto out;
	}

	if ((temp / 1000) > S16_MAX) {
		ret = -EINVAL;
		goto out;
	}

	temperature = (s16)(temp / 1000);
	tzone = &fmac->tz_device;

	if (!tzone) {
		ret = -EIO;
		goto out;
	}

	/* no updates*/
	if (tzone->temp_trips[trip] == temperature) {
		ret = 0;
		goto out;
	}

	/* already existing temperature */
	for (i = 0; i < IWL_MAX_DTS_TRIPS; i++) {
		if (tzone->temp_trips[i] == temperature) {
			ret = -EINVAL;
			goto out;
		}
	}

	tzone->temp_trips[trip] = temperature;

	ret = iwl_fmac_send_temp_report_ths_cmd(fmac);
out:
	mutex_unlock(&fmac->mutex);
	return ret;
}

static void iwl_fmac_notify_thermal_framework_wk(struct work_struct *work)
{
	struct iwl_fmac_thermal_device *tz_dev;
	u32 ths_crossed;

	tz_dev = container_of(work, struct iwl_fmac_thermal_device,
			      notify_thermal_wk);

	ths_crossed = tz_dev->ths_crossed;
	thermal_notify_framework(tz_dev->tzone,
				 tz_dev->fw_trips_index[ths_crossed]);
}

void iwl_fmac_temp_notif(struct iwl_fmac *fmac, struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_dts_measurement_notif_v2 *notif_v2;
	int len = iwl_rx_packet_payload_len(pkt);
	int temp;
	u32 ths_crossed;

	if (WARN_ON_ONCE(len < sizeof(*notif_v2))) {
		IWL_ERR(fmac, "Invalid DTS_MEASUREMENT_NOTIFICATION\n");
		return;
	}

	notif_v2 = (void *)pkt->data;
	ths_crossed = le32_to_cpu(notif_v2->threshold_idx);

	/* 0xFF in ths_crossed means the notification is not related
	 * to a trip, so we can ignore it here.
	 */
	if (ths_crossed == 0xFF)
		return;

	temp = le32_to_cpu(notif_v2->temp);

	/* shouldn't be negative, but since it's s32, make sure it isn't */
	if (WARN_ON_ONCE(temp < 0))
		temp = 0;

	IWL_DEBUG_TEMP(fmac, "Temp = %d Threshold crossed = %d\n",
		       temp, ths_crossed);

	if (WARN_ON(ths_crossed >= IWL_MAX_DTS_TRIPS))
		return;

	fmac->tz_device.ths_crossed = ths_crossed;
	schedule_work(&fmac->tz_device.notify_thermal_wk);
}

static  struct thermal_zone_device_ops tzone_ops = {
	.get_temp = iwl_fmac_tzone_get_temp,
	.get_trip_temp = iwl_fmac_tzone_get_trip_temp,
	.get_trip_type = iwl_fmac_tzone_get_trip_type,
	.set_trip_temp = iwl_fmac_tzone_set_trip_temp,
};

/* make all trips writable */
#define IWL_WRITABLE_TRIPS_MSK (BIT(IWL_MAX_DTS_TRIPS) - 1)

static void iwl_fmac_thermal_zone_register(struct iwl_fmac *fmac)
{
	int i;
	char name[] = "iwlwifi";

	BUILD_BUG_ON(ARRAY_SIZE(name) >= THERMAL_NAME_LENGTH);

	fmac->tz_device.tzone = thermal_zone_device_register(name,
							IWL_MAX_DTS_TRIPS,
							IWL_WRITABLE_TRIPS_MSK,
							fmac, &tzone_ops,
							NULL, 0, 0);
	if (IS_ERR(fmac->tz_device.tzone)) {
		IWL_DEBUG_TEMP(fmac,
			       "Failed to register to thermal zone (err = %ld)\n",
			       PTR_ERR(fmac->tz_device.tzone));
		fmac->tz_device.tzone = NULL;
		return;
	}

	INIT_WORK(&fmac->tz_device.notify_thermal_wk,
		  iwl_fmac_notify_thermal_framework_wk);

	/* 0 is a valid temperature,
	 * so initialize the array with S16_MIN which invalid temperature
	 */
	for (i = 0 ; i < IWL_MAX_DTS_TRIPS; i++)
		fmac->tz_device.temp_trips[i] = S16_MIN;
}

static void iwl_fmac_thermal_zone_unregister(struct iwl_fmac *fmac)
{
	IWL_DEBUG_TEMP(fmac, "Thermal zone device unregister\n");
	if (fmac->tz_device.tzone) {
		thermal_zone_device_unregister(fmac->tz_device.tzone);
		cancel_work_sync(&fmac->tz_device.notify_thermal_wk);
		fmac->tz_device.tzone = NULL;
	}
}

static int iwl_fmac_tcool_get_max_state(struct thermal_cooling_device *cdev,
					unsigned long *state)
{
	*state = ARRAY_SIZE(iwl_fmac_cdev_budgets) - 1;

	return 0;
}

static int iwl_fmac_tcool_get_cur_state(struct thermal_cooling_device *cdev,
					unsigned long *state)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)(cdev->devdata);

	*state = fmac->cooling_dev.cur_state;

	return 0;
}

static int iwl_fmac_tcool_set_cur_state(struct thermal_cooling_device *cdev,
					unsigned long new_state)
{
	struct iwl_fmac *fmac = (struct iwl_fmac *)(cdev->devdata);
	int ret;

	mutex_lock(&fmac->mutex);

	if (!iwl_fmac_firmware_running(fmac) ||
	    fmac->fwrt.cur_fw_img != IWL_UCODE_REGULAR) {
		ret = -EIO;
		goto unlock;
	}

	if (new_state >= ARRAY_SIZE(iwl_fmac_cdev_budgets)) {
		ret = -EINVAL;
		goto unlock;
	}

	ret = iwl_fmac_ctdp_command(fmac, CTDP_CMD_OPERATION_START,
				    new_state);

unlock:
	mutex_unlock(&fmac->mutex);
	return ret;
}

static struct thermal_cooling_device_ops tcooling_ops = {
	.get_max_state = iwl_fmac_tcool_get_max_state,
	.get_cur_state = iwl_fmac_tcool_get_cur_state,
	.set_cur_state = iwl_fmac_tcool_set_cur_state,
};

static void iwl_fmac_cooling_device_register(struct iwl_fmac *fmac)
{
	char name[] = "iwlwifi";

	BUILD_BUG_ON(ARRAY_SIZE(name) >= THERMAL_NAME_LENGTH);

	fmac->cooling_dev.cdev =
		thermal_cooling_device_register(name,
						fmac,
						&tcooling_ops);

	if (IS_ERR(fmac->cooling_dev.cdev)) {
		IWL_DEBUG_TEMP(fmac,
			       "Failed to register to cooling device (err = %ld)\n",
			       PTR_ERR(fmac->cooling_dev.cdev));
		fmac->cooling_dev.cdev = NULL;
		return;
	}
}

static void iwl_fmac_cooling_device_unregister(struct iwl_fmac *fmac)
{
	if (!fmac->cooling_dev.cdev)
		return;

	IWL_DEBUG_TEMP(fmac, "Cooling device unregister\n");
	if (fmac->cooling_dev.cdev) {
		thermal_cooling_device_unregister(fmac->cooling_dev.cdev);
		fmac->cooling_dev.cdev = NULL;
	}
}
#endif

static void iwl_fmac_set_hw_ctkill_state(struct iwl_fmac *fmac, bool state)
{
	if (state)
		set_bit(IWL_STATUS_HW_CTKILL, &fmac->status);
	else
		clear_bit(IWL_STATUS_HW_CTKILL, &fmac->status);

	wiphy_rfkill_set_hw_state(wiphy_from_fmac(fmac),
				  iwl_fmac_is_radio_killed(fmac));
}

static void iwl_fmac_exit_ctkill(struct work_struct *work)
{
	struct iwl_fmac *fmac;

	fmac = container_of(work, struct iwl_fmac, ct_kill_exit.work);

	if (!test_bit(IWL_STATUS_HW_CTKILL, &fmac->status))
		return;

	IWL_ERR(fmac, "Exit CT Kill\n");
	iwl_fmac_set_hw_ctkill_state(fmac, false);
}

void iwl_fmac_enter_ctkill(struct iwl_fmac *fmac)
{
	struct delayed_work *ct_kill_exit = &fmac->ct_kill_exit;
	u32 duration = round_jiffies_relative(IWL_FMAC_CTKILL_DURATION * HZ);

	if (test_bit(IWL_STATUS_HW_CTKILL, &fmac->status))
		return;

	IWL_ERR(fmac, "Enter CT Kill\n");
	iwl_fmac_set_hw_ctkill_state(fmac, true);

	schedule_delayed_work(ct_kill_exit, duration);
}

void iwl_fmac_ct_kill_notif(struct iwl_fmac *fmac,
			    struct iwl_rx_cmd_buffer *rxb)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct ct_kill_notif *notif;
	int len = iwl_rx_packet_payload_len(pkt);

	if (WARN_ON_ONCE(len != sizeof(*notif))) {
		IWL_ERR(fmac, "Invalid CT_KILL_NOTIFICATION\n");
		return;
	}

	notif = (void *)pkt->data;
	IWL_DEBUG_TEMP(fmac, "CT Kill notification temperature = %d\n",
		       notif->temperature);

	iwl_fmac_enter_ctkill(fmac);
}

void iwl_fmac_thermal_initialize(struct iwl_fmac *fmac)
{
	IWL_DEBUG_TEMP(fmac, "Initialize Thermal configuration\n");

	INIT_DELAYED_WORK(&fmac->ct_kill_exit, iwl_fmac_exit_ctkill);

#ifdef CONFIG_THERMAL
	iwl_fmac_cooling_device_register(fmac);
	iwl_fmac_thermal_zone_register(fmac);
#endif
}

void iwl_fmac_thermal_exit(struct iwl_fmac *fmac)
{
	cancel_delayed_work_sync(&fmac->ct_kill_exit);
	IWL_DEBUG_TEMP(fmac, "Exit Thermal\n");

#ifdef CONFIG_THERMAL
	iwl_fmac_cooling_device_unregister(fmac);
	iwl_fmac_thermal_zone_unregister(fmac);
#endif
}


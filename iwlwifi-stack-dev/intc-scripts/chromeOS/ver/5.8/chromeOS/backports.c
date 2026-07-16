void ieee80211_mgmt_frame_register(struct wiphy *wiphy,
				   struct wireless_dev *wdev,
				   u16 frame_type, bool reg)
{
	struct ieee80211_local *local = wiphy_priv(wiphy);
	struct ieee80211_sub_if_data *sdata = IEEE80211_WDEV_TO_SUB_IF(wdev);

	switch (frame_type) {
	case IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ:
		if (reg) {
			local->probe_req_reg = true;
			sdata->vif.probe_req_reg = true;
		} else {
			if (local->probe_req_reg)
				local->probe_req_reg = false;
 
			if (sdata->vif.probe_req_reg)
				sdata->vif.probe_req_reg = false;
		}

		if (!local->open_count)
			break;

		if (ieee80211_sdata_running(sdata)) {
			if (sdata->vif.probe_req_reg == 1)
				drv_config_iface_filter(local, sdata,
							FIF_PROBE_REQ,
							FIF_PROBE_REQ);
			else if (sdata->vif.probe_req_reg == 0)
				drv_config_iface_filter(local, sdata, 0,
							FIF_PROBE_REQ);
		}

		ieee80211_configure_filter(local);
		break;
	default:
		break;
	}
}

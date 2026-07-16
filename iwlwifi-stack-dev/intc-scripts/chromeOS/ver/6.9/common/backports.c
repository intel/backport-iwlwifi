bool cfg80211_iter_rnr(const u8 *elems, size_t elems_len,
		       enum cfg80211_rnr_iter_ret
		       (*iter)(void *data, u8 type,
			       const struct ieee80211_neighbor_ap_info *info,
			       const u8 *tbtt_info, u8 tbtt_info_len),
		       void *iter_data)
{
	const struct element *rnr;
	const u8 *pos, *end;

	for_each_element_id(rnr, WLAN_EID_REDUCED_NEIGHBOR_REPORT,
			    elems, elems_len) {
		const struct ieee80211_neighbor_ap_info *info;

		pos = rnr->data;
		end = rnr->data + rnr->datalen;

		/* RNR IE may contain more than one NEIGHBOR_AP_INFO */
		while (sizeof(*info) <= end - pos) {
			u8 length, i, count;
			u8 type;

			info = (void *)pos;
			count = u8_get_bits(info->tbtt_info_hdr,
					    IEEE80211_AP_INFO_TBTT_HDR_COUNT) +
				1;
			length = info->tbtt_info_len;

			pos += sizeof(*info);

			if (count * length > end - pos)
				return false;

			type = u8_get_bits(info->tbtt_info_hdr,
					   IEEE80211_AP_INFO_TBTT_HDR_TYPE);

			for (i = 0; i < count; i++) {
				switch (iter(iter_data, type, info,
					     pos, length)) {
				case RNR_ITER_CONTINUE:
					break;
				case RNR_ITER_BREAK:
					return true;
				case RNR_ITER_ERROR:
					return false;
				}

				pos += length;
			}
		}

		if (pos != end)
			return false;
	}

	return true;
}

ssize_t cfg80211_defragment_element(const struct element *elem, const u8 *ies,
				    size_t ieslen, u8 *data, size_t data_len,
				    u8 frag_id)
{
	const struct element *next;
	ssize_t copied;
	u8 elem_datalen;

	if (!elem)
		return -EINVAL;

	/* elem might be invalid after the memmove */
	next = (void *)(elem->data + elem->datalen);
	elem_datalen = elem->datalen;

	if (elem->id == WLAN_EID_EXTENSION) {
		copied = elem->datalen - 1;

		if (data) {
			if (copied > data_len)
				return -ENOSPC;

			memmove(data, elem->data + 1, copied);
		}
	} else {
		copied = elem->datalen;

		if (data) {
			if (copied > data_len)
				return -ENOSPC;

			memmove(data, elem->data, copied);
		}
	}

	/* Fragmented elements must have 255 bytes */
	if (elem_datalen < 255)
		return copied;

	for (elem = next;
	     elem->data < ies + ieslen &&
		elem->data + elem->datalen <= ies + ieslen;
	     elem = next) {
		/* elem might be invalid after the memmove */
		next = (void *)(elem->data + elem->datalen);

		if (elem->id != frag_id)
			break;

		elem_datalen = elem->datalen;

		if (data) {
			if (copied + elem_datalen > data_len)
				return -ENOSPC;

			memmove(data + copied, elem->data, elem_datalen);
		}

		copied += elem_datalen;

		/* Only the last fragment may be short */
		if (elem_datalen != 255)
			break;
	}

	return copied;
}
EXPORT_SYMBOL(cfg80211_defragment_element);

bool ieee80211_operating_class_to_chandef(u8 operating_class,
					  struct ieee80211_channel *chan,
					  struct cfg80211_chan_def *chandef)
{
	u32 control_freq, offset = 0;
	enum nl80211_band band;

	if (!ieee80211_operating_class_to_band(operating_class, &band) ||
	    !chan || band != chan->band)
		return false;

	control_freq = chan->center_freq;
	chandef->chan = chan;

	if (control_freq >= 5955)
		offset = control_freq - 5955;
	else if (control_freq >= 5745)
		offset = control_freq - 5745;
	else if (control_freq >= 5180)
		offset = control_freq - 5180;
	offset /= 20;

	switch (operating_class) {
	case 81:  /* 2 GHz band; 20 MHz; channels 1..13 */
	case 82:  /* 2 GHz band; 20 MHz; channel 14 */
	case 115: /* 5 GHz band; 20 MHz; channels 36,40,44,48 */
	case 118: /* 5 GHz band; 20 MHz; channels 52,56,60,64 */
	case 121: /* 5 GHz band; 20 MHz; channels 100..144 */
	case 124: /* 5 GHz band; 20 MHz; channels 149,153,157,161 */
	case 125: /* 5 GHz band; 20 MHz; channels 149..177 */
	case 131: /* 6 GHz band; 20 MHz; channels 1..233*/
	case 136: /* 6 GHz band; 20 MHz; channel 2 */
		chandef->center_freq1 = control_freq;
		chandef->width = NL80211_CHAN_WIDTH_20;
		return true;
	case 83:  /* 2 GHz band; 40 MHz; channels 1..9 */
	case 116: /* 5 GHz band; 40 MHz; channels 36,44 */
	case 119: /* 5 GHz band; 40 MHz; channels 52,60 */
	case 122: /* 5 GHz band; 40 MHz; channels 100,108,116,124,132,140 */
	case 126: /* 5 GHz band; 40 MHz; channels 149,157,165,173 */
		chandef->center_freq1 = control_freq + 10;
		chandef->width = NL80211_CHAN_WIDTH_40;
		return true;
	case 84:  /* 2 GHz band; 40 MHz; channels 5..13 */
	case 117: /* 5 GHz band; 40 MHz; channels 40,48 */
	case 120: /* 5 GHz band; 40 MHz; channels 56,64 */
	case 123: /* 5 GHz band; 40 MHz; channels 104,112,120,128,136,144 */
	case 127: /* 5 GHz band; 40 MHz; channels 153,161,169,177 */
		chandef->center_freq1 = control_freq - 10;
		chandef->width = NL80211_CHAN_WIDTH_40;
		return true;
	case 132: /* 6 GHz band; 40 MHz; channels 1,5,..,229*/
		chandef->center_freq1 = control_freq + 10 - (offset & 1) * 20;
		chandef->width = NL80211_CHAN_WIDTH_40;
		return true;
	case 128: /* 5 GHz band; 80 MHz; channels 36..64,100..144,149..177 */
	case 133: /* 6 GHz band; 80 MHz; channels 1,5,..,229 */
		chandef->center_freq1 = control_freq + 30 - (offset & 3) * 20;
		chandef->width = NL80211_CHAN_WIDTH_80;
		return true;
	case 129: /* 5 GHz band; 160 MHz; channels 36..64,100..144,149..177 */
	case 134: /* 6 GHz band; 160 MHz; channels 1,5,..,229 */
		chandef->center_freq1 = control_freq + 70 - (offset & 7) * 20;
		chandef->width = NL80211_CHAN_WIDTH_160;
		return true;
	case 130: /* 5 GHz band; 80+80 MHz; channels 36..64,100..144,149..177 */
	case 135: /* 6 GHz band; 80+80 MHz; channels 1,5,..,229 */
		  /* The center_freq2 of 80+80 MHz is unknown */
	case 137: /* 6 GHz band; 320 MHz; channels 1,5,..,229 */
		  /* 320-1 or 320-2 channelization is unknown */
	default:
		return false;
	}
}

int cfg80211_chandef_primary(const struct cfg80211_chan_def *c,
			     enum nl80211_chan_width primary_chan_width,
			     u16 *punctured)
{
	int pri_width = nl80211_chan_width_to_mhz(primary_chan_width);
	int width = cfg80211_chandef_get_width(c);
	u32 control = c->chan->center_freq;
	u32 center = c->center_freq1;
	u16 _punct = 0;

	if (WARN_ON_ONCE(pri_width < 0 || width < 0))
		return -1;

	/* not intended to be called this way, can't determine */
	if (WARN_ON_ONCE(pri_width > width))
		return -1;

	if (!punctured)
		punctured = &_punct;

#if LINUX_VERSION_IS_GEQ(6,9,0)
	*punctured = c->punctured;
#endif

	while (width > pri_width) {
		unsigned int bits_to_drop = width / 20 / 2;

		if (control > center) {
			center += width / 4;
			*punctured >>= bits_to_drop;
		} else {
			center -= width / 4;
			*punctured &= (1 << bits_to_drop) - 1;
		}
		width /= 2;
	}

	return center;
}

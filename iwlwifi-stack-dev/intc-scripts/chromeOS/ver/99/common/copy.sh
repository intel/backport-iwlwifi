sed -i '/nan\.o/d' "$kernel_path/drivers/net/wireless/iwl7000/mac80211/Makefile"

rm -f "$kernel_path/drivers/net/wireless/iwl7000/mac80211/nan.c"

cp "$driver_path/include/linux/bitfield.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/linux/"
sed 's%#include <hdrs/linux/ieee80211.h>%#include <hdrs/linux/bitfield.h>\n\0%' \
  -i "$kernel_path/drivers/net/wireless/iwl7000/hdrs/iwl-chrome.h"

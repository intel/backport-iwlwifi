rm -rf "$kernel_path/drivers/net/wireless/iwl7000/iwlwifi/mld/"

sed -i '/CPTCFG_IWLMLD/d' $kernel_path/drivers/net/wireless/iwl7000/iwlwifi/Makefile

sed -i '/^config IWL7000_MLD/,/^$/d' $kernel_path/drivers/net/wireless/iwl7000/Kconfig

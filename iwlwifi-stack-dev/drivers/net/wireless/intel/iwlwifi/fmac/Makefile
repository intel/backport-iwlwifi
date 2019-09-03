obj-$(CPTCFG_IWLFMAC) += iwlfmac.o
iwlfmac-y += ops.o cfg.o iface.o tx.o rx.o fw.o nvm.o sta.o
iwlfmac-y += vendor-cmd.o tt.o
iwlfmac-$(CPTCFG_CFG80211_DEBUGFS) += debugfs.o

ccflags-y += -D__CHECK_ENDIAN__ -I$(src)/../

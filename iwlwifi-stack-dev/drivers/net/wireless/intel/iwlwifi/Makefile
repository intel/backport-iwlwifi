# SPDX-License-Identifier: GPL-2.0
# common
obj-$(CPTCFG_IWLWIFI)	+= iwlwifi.o
iwlwifi-objs		+= iwl-io.o
iwlwifi-objs		+= iwl-drv.o
iwlwifi-objs		+= iwl-debug.o
iwlwifi-objs		+= iwl-nvm-utils.o
iwlwifi-objs		+= iwl-utils.o
iwlwifi-objs		+= iwl-phy-db.o iwl-nvm-parse.o

iwlwifi-objs		+= iwl-dbg-tlv.o
iwlwifi-objs		+= iwl-trans.o

iwlwifi-objs		+= fw/img.o fw/notif-wait.o fw/rs.o
iwlwifi-objs		+= fw/dbg.o fw/pnvm.o fw/dump.o
iwlwifi-objs		+= fw/regulatory.o
iwlwifi-$(CPTCFG_IWLMVM) += fw/paging.o fw/smem.o fw/init.o
iwlwifi-$(CPTCFG_IWLMLD) += fw/smem.o fw/init.o
iwlwifi-$(CONFIG_ACPI) += fw/acpi.o
iwlwifi-$(CONFIG_EFI)	+= fw/uefi.o

iwlwifi-$(CPTCFG_IWLXVT)	+= fw/paging.o fw/smem.o
iwlwifi-$(CPTCFG_IWLPROD)	+= fw/init.o
iwlwifi-$(CPTCFG_IWLXVT)	+= fw/init.o
iwlwifi-$(CPTCFG_IWLWIFI_DEBUGFS) += fw/debugfs.o

# Mock-ups
iwlwifi-$(CPTCFG_IWLWIFI_PLATFORM_MOCKUPS) += fw/acpi.o fw/uefi.o
iwlwifi-$(CPTCFG_IWLWIFI_PLATFORM_MOCKUPS) += fw/platform-mockups.o

# Bus
iwlwifi-$(CONFIG_PCI) += pcie/ctxt-info.o pcie/ctxt-info-v2.o pcie/drv.o pcie/utils.o
iwlwifi-$(CONFIG_PCI) += pcie/gen1_2/rx.o pcie/gen1_2/tx.o pcie/gen1_2/trans.o
iwlwifi-$(CONFIG_PCI) += pcie/gen1_2/trans-gen2.o pcie/gen1_2/tx-gen2.o
iwlwifi-$(CONFIG_PCI) += pcie/gen3/trans.o pcie/gen3/interrupts.o

CFLAGS_pcie/drv.o += -Wno-override-init

# combined MAC/RF configurations
iwlwifi-$(CPTCFG_IWLDVM) += cfg/1000.o cfg/2000.o
iwlwifi-$(CPTCFG_IWLDVM) += cfg/5000.o cfg/6000.o
iwlwifi-$(CPTCFG_IWLMVM) += cfg/7000.o cfg/8000.o
# MAC configurations
iwlwifi-$(CPTCFG_IWLMVM) += cfg/9000.o cfg/22000.o
iwlwifi-$(CPTCFG_IWLMVM) += cfg/ax210.o
iwlwifi-$(CPTCFG_IWLMVM) += cfg/bz.o cfg/sc.o
iwlwifi-$(CPTCFG_IWLMLD) += cfg/bz.o cfg/sc.o cfg/dr.o
# RF configurations
iwlwifi-$(CPTCFG_IWLMVM) += cfg/rf-jf.o cfg/rf-hr.o cfg/rf-gf.o
iwlwifi-$(CPTCFG_IWLMLD) += cfg/rf-fm.o cfg/rf-wh.o cfg/rf-pe.o

iwlwifi-$(CPTCFG_IWLWIFI_SUPPORT_DEBUG_OVERRIDES) += iwl-dbg-cfg.o

iwlwifi-objs += $(iwlwifi-m)
iwlwifi-objs += $(iwlwifi-y)

iwlwifi-$(CPTCFG_IWLWIFI_DEVICE_TRACING) += iwl-devtrace.o
iwlwifi-$(CPTCFG_IWLWIFI_DEVICE_TESTMODE) += iwl-tm-gnl.o fw/testmode.o

ccflags-y += -I$(src)
subdir-ccflags-y += $(call cc-option,-Wimplicit-fallthrough)
# for FreeBSD compatibility - they use most of our driver
subdir-ccflags-$(CPTCFG_IWLWIFI_SIMULATION) += $(call cc-option,-Wcast-qual)
subdir-ccflags-$(CPTCFG_IWLWIFI_SIMULATION) += $(call cc-option,-Wpointer-arith)

obj-$(CPTCFG_IWLDVM)	+= dvm/
obj-$(CPTCFG_IWLMVM)	+= mvm/
obj-$(CPTCFG_IWLMEI)	+= mei/
obj-$(CPTCFG_IWLXVT)	+= xvt/
obj-$(CPTCFG_IWLPROD)	+= prod/
obj-$(CPTCFG_IWLMLD)	+= mld/

obj-$(CPTCFG_IWLWIFI_KUNIT_TESTS) += tests/

CFLAGS_iwl-devtrace.o := -I$(src)

ifeq ($(CPTCFG_IWLWIFI_SIMULATION),y)
UBSAN_SANITIZE := y
obj-$(CPTCFG_IWLWIFI_SIMULATION) += simulation/
endif

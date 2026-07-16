#ifndef __BACKPORT_H
#define __BACKPORT_H
#include <generated/autoconf.h>
#ifndef CONFIG_BACKPORT_INTEGRATE
#include <backport/autoconf.h>
#endif
#include <linux/kconfig.h>

#ifndef __ASSEMBLY__
#define LINUX_BACKPORT(__sym) backport_ ##__sym
#ifndef CONFIG_BACKPORT_INTEGRATE
#include <backport/checks.h>
#endif
#endif

#ifdef CPTCFG_IWLWIFI_PRE_SILICON_SUPPORT
extern unsigned int iwl_timeout_factor;
extern unsigned int iwl_delay_factor;
extern unsigned int iwl_pre_si_fpga;
#endif

#endif /* __BACKPORT_H */

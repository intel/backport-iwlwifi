#define NL80211_EXT_FEATURE_AQL -1

#define IEEE80211_DEFAULT_AQL_TXQ_LIMIT_L	5000
#define IEEE80211_DEFAULT_AQL_TXQ_LIMIT_H	12000
#define IEEE80211_AQL_THRESHOLD			24000

#define kcov_remote_start_common(id) {}
#define kcov_remote_stop() {}

#include <linux/debugfs.h>

#define debugfs_create_xul iwl7000_debugfs_create_xul
static inline void debugfs_create_xul(const char *name, umode_t mode,
				      struct dentry *parent,
				      unsigned long *value)
{
	if (sizeof(*value) == sizeof(u32))
		debugfs_create_x32(name, mode, parent, (u32 *)value);
	else
		debugfs_create_x64(name, mode, parent, (u64 *)value);
}

#ifndef PCI_STD_NUM_BARS
#define PCI_STD_NUM_BARS 6
#endif


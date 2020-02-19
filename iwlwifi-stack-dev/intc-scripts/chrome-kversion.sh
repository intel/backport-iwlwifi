#!/bin/bash

set -e

# start with the kernel Google are planning to use next
START='4.20'
KGIT='https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git'

if ! test -d linux ; then
	git clone $KGIT
	cd linux
else
	cd linux
	git remote set-url origin $KGIT
	git remote update
fi

err=0
SUCCESS=""
GEN_FAIL=""
MAKE_FAIL=""
PROD_FAIL=""

# this is a complicated pipeline...
# - git tag:	get all tags
# - grep:	only use vX.Y.Z
# - sort:	sort reserve by version (v4.10 before v4.9.x etc.)
# - grep:	get everything before (due to reserve sort) start version
# - sort:	sort again, only on vX.Y (ignoring .Z and further fields
#		separated by dots), and get (-u) only the first match
# as a result this identifies all the highest-numbered stable tags of kernel
# versions higher than the starting version
for tag in $(git tag | grep 'v[4-9]\.[0-9]\+\(\.[0-9]\+\)\?$' | \
	     sort --version-sort -r | grep -B1000 "^v${START}$" | \
	     sort --version-sort -u -t. -k1,2 ) ; do
	echo "******** generate and compile against $tag"
	git reset --hard $tag
	git clean -fdxq
	echo "CONFIG_CFG80211=m" >> .config
	echo "CONFIG_PCI=y" >> .config
	echo "CONFIG_NET=y" >> .config
	echo "CONFIG_IWL7000=m" >> .config
	echo "CONFIG_IWL7000_LEDS=y" >> .config
	echo "CONFIG_EVENT_TRACING=y" >> .config
	echo "CONFIG_NL80211_TESTMODE=y" >> .config
	echo "CONFIG_CFG80211_DEBUGFS=y" >> .config
	echo "CONFIG_DEBUG_FS=y" >> .config
	echo "CONFIG_NETDEVICES=y" >> .config
	echo "CONFIG_MODULES=y" >> .config
	if ! ../iwlwifi-stack-dev/intc-scripts/chromeOS/copy.sh \
		../iwlwifi-stack-dev/. . HEAD ; then
		err=1
		echo ">>>>>>>> failed to generate against $tag"
		GEN_FAIL="$GEN_FAIL $tag"
	fi
	yes '' | make oldconfig
	if ! make -j8 drivers/net/wireless/iwl7000/ ; then
		err=1
		echo ">>>>>>>> failed to build against $tag"
		MAKE_FAIL="$MAKE_FAIL $tag"
	elif ! test -f drivers/net/wireless/iwl7000/iwlwifi/iwlwifi.o ; then
		err=1
		echo ">>>>>>>> compilation against $tag had no output"
		PROD_FAIL="$PROD_FAIL $tag"
	else
		echo ">>>>>>>> successfully compiled against $tag"
		SUCCESS="$SUCCESS $tag"
	fi
done

if [ -n "$SUCCESS" ] ; then
	echo "successfully compiled against: $SUCCESS"
fi
if [ -n "$GEN_FAIL" ] ; then
	echo "failed to generate against:$GEN_FAIL"
fi
if [ -n "$MAKE_FAIL" ] ; then
	echo "failed to build against:$MAKE_FAIL"
fi
if [ -n "$PROD_FAIL" ] ; then
	echo "failed to produce output for:$PROD_FAIL"
fi
exit $err

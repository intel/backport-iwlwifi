#!/bin/bash
#
# Copy the given stack-dev tree (must be pruned) into ChromeOS tree
# to drivers/net/wireless$WIFIVERSON/iwl7000/
#
# Requires WIFIVERSION in the environment where needed.
#

set -e

UNIFDEF=$(which unifdef)

if [ -z "$1" ] || [ -z "$2" ] ; then
	echo "Please run $0 /path/to/iwlwifi-stack-auto/ /path/to/kernel/"
	exit 2
fi

driver_path="$1"
kernel_path="$2"
source_path="$(dirname "$(readlink -e "$0")")"


# if it's already there we'll update
if [ -d "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/" ] ; then
	rm -rf "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"
fi

# if not patched, then patch it in
if ! grep -q IWL7000 "$kernel_path/drivers/net/wireless$WIFIVERSION/Makefile"; then
	echo 'obj-$(CONFIG_IWL7000) += iwl7000/' >> "$kernel_path/drivers/net/wireless$WIFIVERSION/Makefile"
	sed -i "s%endif # WLAN%source \"drivers/net/wireless$WIFIVERSION/iwl7000/Kconfig\"\n\0%" \
		"$kernel_path/drivers/net/wireless$WIFIVERSION/Kconfig"
	test -f "$kernel_path/drivers/net/wireless$WIFIVERSION/iwlwifi/Kconfig" && \
		sed -i '0, /depends on/ s/\s*depends on .*/\0 \&\& IWL7000=n/' \
			"$kernel_path/drivers/net/wireless$WIFIVERSION/iwlwifi/Kconfig"
fi

mkdir "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"

# copy all the source files we need to the right places
cp "$source_path/Kconfig" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"
cp "$source_path/Makefile" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"
cp -ar "$driver_path/net/mac80211/" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"
cp -ar "$source_path/reg.c" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/"
cp -ar "$source_path/cfg-utils.c" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/"
cp -ar "$source_path/backports.c" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/"
rm -f "$kernel_path"/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/mesh*c
rm -f "$kernel_path"/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/rc80211*
cp -ar "$driver_path/drivers/net/wireless/intel/iwlwifi/" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"
rm -f "$kernel_path"/drivers/net/wireless$WIFIVERSION/iwl7000/*/Kconfig*

# and patch the sources
patch -p2 --reject-file=/dev/stdout -d "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/" < "$source_path/mac80211.patch"
patch -p5 --reject-file=/dev/stdout -d "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/" < "$source_path/iwlwifi.patch"

# apply the adjustments.spatch
# it has some special handling, first we grep out the CFG80211_TESTMODE_CMD
# and CFG80211_TESTMODE_DUMP from the cfg80211_ops and iwl_mvm_hw_ops, because
# spatch fails to parse structs with those present. We then store these diffs
# and apply it back later, restoring them ... this works because right now we
# don't need to actually patch the ops in their vicinity. Otherwise we could
# find some other way of putting them back.
grep -v CFG80211_TESTMODE_ "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c" \
	> "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c_NOTESTMODE"
grep -v CFG80211_TESTMODE_ "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c" \
	> "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c_NOTESTMODE"
diff -u "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c" \
	"$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c_NOTESTMODE" \
	> "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c_DIFF" || true
diff -u "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c" \
	"$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c_NOTESTMODE" \
	> "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c_DIFF" || true
rm -f "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c"
rm -f "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c"
mv "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c_NOTESTMODE" \
	"$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c"
mv "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c_NOTESTMODE" \
	"$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c"
# now the spatch will apply ...
spatch --include-headers --sp-file "$source_path/adjustments.spatch" --in-place --dir "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/" &
spatch --include-headers --sp-file "$source_path/adjustments.spatch" --in-place --dir "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/"
wait
# now put back the diffs
( # patch needs to be in / to use absolute paths without prompting ...
cd /
cat "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c_DIFF" | sed 's/_NOTESTMODE//' | patch -p0 -R
cat "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c_DIFF" | sed 's/_NOTESTMODE//' | patch -p0 -R
)
rm -f "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/iwlwifi/mvm/mac80211.c_DIFF"
rm -f "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/cfg.c_DIFF"

# remove wext includes
find $kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/ -name '*.[ch]' |xargs sed -i 's/wext-compat\.h//;T;d'

mkdir -p "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/"{net,linux}

# copy these after spatch - otherwise it may modify it!
cp -ar "$source_path/hdrs/" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/"
cp "$driver_path/include/linux/ieee80211.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/"
cp "$driver_path/include/net/mac80211.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/net/"
cp "$driver_path/include/net/ieee80211_radiotap.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/net/"
cp "$driver_path/include/linux/average.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/"
cp "$driver_path/include/linux/bitfield.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/"
cp "$driver_path/include/linux/overflow.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/"
cp "$driver_path/include/net/codel.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/net/"
cp "$driver_path/include/net/codel_impl.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/net/"
cp "$driver_path/include/net/fq.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/net/"
cp "$driver_path/include/net/fq_impl.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/net/"

cp "$driver_path/backport-include/backport/magic.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/"
cp "$driver_path/backport-include/linux/build_bug.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/"

# handle rhashtable - add our version thereof
cp "$driver_path/include/linux/backport-rhashtable.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/rhashtable.h"
cp "$driver_path/include/linux/backport-rhashtable-types.h" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/linux/rhashtable-types.h"
cp "$driver_path/compat/lib-rhashtable.c" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/rhashtable.c"
sed -i 's/^mac80211-.*pm.o/\0\nmac80211-y += rhashtable.o/' "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/Makefile"

# handle bucket_locks - add our version thereof
cp "$driver_path/compat/lib-bucket_locks.c" "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/bucket_locks.c"
sed -i 's/^mac80211-.*pm.o/\0\nmac80211-y += bucket_locks.o/' "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/Makefile"

# Add the header file required to rename all the symbols - this
# makes our driver compatible with installing and loading other
# drivers that also use mac80211 (the native version, not ours)
(
echo '#ifndef __MAC80211_EXP_H'
echo '#define __MAC80211_EXP_H'
ls "$kernel_path"/drivers/net/wireless$WIFIVERSION/iwl7000/mac80211/*.c \
	| LC_ALL=C sort | xargs cat | "$source_path/parse-symbols.py"
echo '#endif'
) > "$kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/hdrs/mac80211-exp.h"

for fn in $(find $kernel_path/drivers/net/wireless$WIFIVERSION/iwl7000/ -name '*.[ch]') ; do
	# run unifdef to remove "#if 0" blocks
	# (which we used to have in the patches, not any more though)
	mv $fn $fn.pre
	set +e
	$UNIFDEF -B -k < $fn.pre > $fn
	r=$?
	set -e
	rm $fn.pre
	if [ $r -ne 0 ] && [ $r -ne 1 ] ; then
		# abort
		echo "unifdef failure - " $r
		false
	fi

	# Remove trailing whitespaces - spatch sometimes adds them by mistake,
	# for example when adding a new function argument in a line by itself
	# while there are more arguments later.
	sed  -i 's/\s*$//' $fn
done

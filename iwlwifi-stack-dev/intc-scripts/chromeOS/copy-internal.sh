#!/bin/bash
#
# Copy the given stack-dev tree (must be pruned) into ChromeOS tree
# to drivers/net/wireless/iwl7000/, or for Android to the separate
# iwl7000 repository layout.
#

set -e

UNIFDEF=$(which unifdef)
ANDROID_FILE="$(dirname "$0")/android.yaml"

if [ "$1" = "--simulation" ] ; then
  SIMULATION=1
  shift
else
  SIMULATION=0
fi

case "$1" in
--android=*|--android-pre=*) # -pre is only for compat
    android=1
    _android_name="${1//*=}"
    KERNEL_VERSION="$(yq -cr '.[]."'${_android_name}'" // "" | .[]."kernel-version"' < $ANDROID_FILE)"
    _dirname="$(yq -cr '.[]."'${_android_name}'" // "" | .[].dirname' < $ANDROID_FILE)"
    android_build_file="$(yq -cr '.[]."'${_android_name}'" // "" | .[].buildfile' < $ANDROID_FILE)"
    OSES="android ${_dirname}"
    shift
    ;;
--aluminium)
    OSES="android android-6.6"
    android=0
    KERNEL_VERSION=
    shift
    ;;
*)
    OSES="chromeOS"
    android=0
    KERNEL_VERSION=
    ;;
esac

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Please run $0 [--simulation] [--android=<kernelversion>] /path/to/iwlwifi-stack-auto/ /path/to/kernel/"
    exit 2
fi

driver_path="$1"
kernel_path="$2"
source_path="$(dirname "$(readlink -e "$0")")"

echo '=== tool versions ==='
echo "$(which spatch):"
spatch --version
echo "---"
echo "$UNIFDEF:"
$UNIFDEF -V
echo "---"
echo "$(which patch):"
patch --version
echo '==='

if [ "$KERNEL_VERSION" = "" ] ; then
    # there's probably a better way to do this, but who cares?
    KERNEL_VERSION=$((grep -E '^(VERSION|PATCHLEVEL)\s*=' $kernel_path/Makefile | \
                      sed 's/\s*//g' ; echo echo '$VERSION.$PATCHLEVEL' ) | sh)
fi
echo "kernel version: $KERNEL_VERSION"

# get versions we know adjustments for
KNOWN_VERSIONS=$(ls $source_path/ver/ | sort --version-sort)
echo "have backports for: " $KNOWN_VERSIONS

_NEEDED_VERSIONS=$((echo $KNOWN_VERSIONS ; echo ${KERNEL_VERSION}=STOP)|tr ' ' '\n' | sort --version-sort | grep -A99 =STOP|grep -v =STOP || true)
echo "apply backports for: " ${_NEEDED_VERSIONS}
NEEDED_VERSIONS=
NEEDED_VERSIONS_REV=
for v in ${_NEEDED_VERSIONS} ; do
  # deal with old cores for now - they get a new script for android
  if [ "$android" = "1" ] ; then
    NEEDED_VERSIONS="$NEEDED_VERSIONS ver/$v"
    NEEDED_VERSIONS_REV="ver/$v $NEEDED_VERSIONS_REV"
  fi
  NEEDED_VERSIONS="$NEEDED_VERSIONS ver/$v/common"
  NEEDED_VERSIONS_REV="ver/$v/common $NEEDED_VERSIONS_REV"
  for os in $OSES ; do
    NEEDED_VERSIONS="$NEEDED_VERSIONS ver/$v/$os"
    NEEDED_VERSIONS_REV="ver/$v/$os $NEEDED_VERSIONS_REV"
  done
done

if [ "$android" = "1" ] ; then
  # Android starts completely from scratch (but don't delete .git!)
  rm -rf "$kernel_path"/*
else
  # if it's already there we'll update
  if [ -d "$kernel_path/drivers/net/wireless/iwl7000/" ] ; then
    rm -rf "$kernel_path/drivers/net/wireless/iwl7000/"
  fi

  # if not patched, then patch it in
  if ! grep -q IWL7000 "$kernel_path/drivers/net/wireless/Makefile"; then
	echo 'obj-$(CONFIG_IWL7000) += iwl7000/' >> "$kernel_path/drivers/net/wireless/Makefile"
	sed -i "s%endif # WLAN%source \"drivers/net/wireless/iwl7000/Kconfig\"\n\0%" \
		"$kernel_path/drivers/net/wireless/Kconfig"
	test -f "$kernel_path/drivers/net/wireless/iwlwifi/Kconfig" && \
		sed -i '0, /depends on/ s/\s*depends on .*/\0 \&\& IWL7000=n/' \
			"$kernel_path/drivers/net/wireless/iwlwifi/Kconfig"
  fi
fi

# for android we'll move things out later and rmdir this
mkdir -p "$kernel_path/drivers/net/wireless/iwl7000/"

# copy all the source files we need to the right places
if [ "$android" != "1" ] ; then
  cp "$source_path/Makefile" "$kernel_path/drivers/net/wireless/iwl7000/"
  cp "$source_path/Kconfig" "$kernel_path/drivers/net/wireless/iwl7000/"
fi
cp -ar "$driver_path/net/mac80211/" "$kernel_path/drivers/net/wireless/iwl7000/"
cp -ar "$source_path/backports.c" "$kernel_path/drivers/net/wireless/iwl7000/mac80211/"
for v in $NEEDED_VERSIONS ; do
    for f in $(ls $source_path/$v/*.c 2>/dev/null) ; do
        echo >> $kernel_path/drivers/net/wireless/iwl7000/mac80211/backports.c
        cat $f >> $kernel_path/drivers/net/wireless/iwl7000/mac80211/backports.c
    done
done
rm -f "$kernel_path"/drivers/net/wireless/iwl7000/mac80211/mesh*c
rm -f "$kernel_path"/drivers/net/wireless/iwl7000/mac80211/rc80211*
cp -ar "$driver_path/drivers/net/wireless/intel/iwlwifi/" "$kernel_path/drivers/net/wireless/iwl7000/"
rm -f "$kernel_path"/drivers/net/wireless/iwl7000/*/Kconfig*

# create header dirs and copy mac80211.h
mkdir -p "$kernel_path/drivers/net/wireless/iwl7000/hdrs/"{net,linux,crypto,kunit,mei}
cp "$driver_path/include/net/mac80211.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/net/"

# apply the patches and spatches
# This has some special handling, first we grep out the CFG80211_TESTMODE_CMD
# and CFG80211_TESTMODE_DUMP from the cfg80211_ops and iwl_mvm_hw_ops, because
# spatch fails to parse structs with those present, but also because we just
# don't need them and in fact cannot have them since the functions are removed.
grep -v CFG80211_TESTMODE_ "$kernel_path/drivers/net/wireless/iwl7000/iwlwifi/mvm/mac80211.c" \
	> "$kernel_path/drivers/net/wireless/iwl7000/iwlwifi/mvm/mac80211.c_NOTESTMODE"
grep -v CFG80211_TESTMODE_ "$kernel_path/drivers/net/wireless/iwl7000/mac80211/cfg.c" \
	> "$kernel_path/drivers/net/wireless/iwl7000/mac80211/cfg.c_NOTESTMODE"
rm -f "$kernel_path/drivers/net/wireless/iwl7000/iwlwifi/mvm/mac80211.c"
rm -f "$kernel_path/drivers/net/wireless/iwl7000/mac80211/cfg.c"
mv "$kernel_path/drivers/net/wireless/iwl7000/iwlwifi/mvm/mac80211.c_NOTESTMODE" \
	"$kernel_path/drivers/net/wireless/iwl7000/iwlwifi/mvm/mac80211.c"
mv "$kernel_path/drivers/net/wireless/iwl7000/mac80211/cfg.c_NOTESTMODE" \
	"$kernel_path/drivers/net/wireless/iwl7000/mac80211/cfg.c"


echo "Applying patches and semantic patches ..."
tmp=$(mktemp)
NPROC=$(nproc 2>/dev/null || echo 1)
for v in $NEEDED_VERSIONS_REV ; do
    for f in $(ls $source_path/$v/*.patch 2>/dev/null) ; do
        echo "Applying $v/$(basename $f) ..."
        patch --posix -p2 --reject-file=${tmp} -d "$kernel_path/drivers/net/wireless/iwl7000/" < "$f"
    done
    for sp in $(ls $source_path/$v/*.spatch 2>/dev/null | sort ); do
        echo "Applying" $v/$(basename $sp)
        spatch --jobs $NPROC --very-quiet --no-show-diff --include-headers --sp-file $sp --in-place --dir "$kernel_path/drivers/net/wireless/iwl7000/"
    done
done

# remove wext includes
find $kernel_path/drivers/net/wireless/iwl7000/ -name '*.[ch]' |xargs sed -i 's/wext-compat\.h//;T;d'

sed 's/IS_ENABLED(CPTCFG_IWLMEI)/0/' < "$source_path/hdrs/mei/iwl-mei.h" | \
  unifdef -x1 -B -k > "$kernel_path/drivers/net/wireless/iwl7000/hdrs/mei/iwl-mei.h"
rm -f "$source_path/hdrs/mei/iwl-mei.h"

# copy these after spatch - otherwise it may modify it!
cp -ar "$source_path/hdrs/" "$kernel_path/drivers/net/wireless/iwl7000/"
INSERT='// DEFINITIONS INSERTED HERE //'
(
    cat "$source_path/hdrs/iwl-chrome.h" | grep -B10000 "$INSERT" | grep -v "$INSERT"
    for v in $NEEDED_VERSIONS_REV ; do
        for f in $(ls $source_path/$v/*-defs.h 2>/dev/null) ; do
            echo ""
            cat $f
        done
    done
    cat "$source_path/hdrs/iwl-chrome.h" | grep -A10000 "$INSERT" | grep -v "$INSERT"
) > "$kernel_path/drivers/net/wireless/iwl7000/hdrs/iwl-chrome.h"

for v in $NEEDED_VERSIONS ; do
    for f in $(ls $source_path/$v/*.h 2>/dev/null) ; do
        if [ "${f: -7}" != "-defs.h" ] ; then
            echo >> $kernel_path/drivers/net/wireless/iwl7000/hdrs/backports.h
            cat $f >> $kernel_path/drivers/net/wireless/iwl7000/hdrs/backports.h
        fi
    done
done

cp "$driver_path"/include/linux/ieee80211*.h "$kernel_path/drivers/net/wireless/iwl7000/hdrs/linux/"
cp "$driver_path/include/net/ieee80211_radiotap.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/net/"
cp "$driver_path/include/linux/units.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/linux/"
cp "$driver_path/include/net/codel.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/net/"
cp "$driver_path/include/net/codel_impl.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/net/"
cp "$driver_path/include/net/fq.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/net/"
cp "$driver_path/include/net/fq_impl.h" "$kernel_path/drivers/net/wireless/iwl7000/hdrs/net/"

for v in $NEEDED_VERSIONS ; do
    if test -f $source_path/$v/copy.sh ; then
        . $source_path/$v/copy.sh
    fi
    if test -d $source_path/$v/hdrs ; then
        cp -r $source_path/$v/hdrs/* "$kernel_path/drivers/net/wireless/iwl7000/hdrs/"
    fi
done

for fn in $(find $kernel_path/drivers/net/wireless/iwl7000/ -name 'Makefile*') ; do
	# remove implicit fallthrough warnings due to issues with clang
	sed -i '/-Wimplicit-fallthrough/d' $fn
done

# Add the header file required to rename all the symbols - this
# makes our driver compatible with installing and loading other
# drivers that also use mac80211 (the native version, not ours)
(
echo '#ifndef __MAC80211_EXP_H'
echo '#define __MAC80211_EXP_H'
ls "$kernel_path"/drivers/net/wireless/iwl7000/mac80211/*.c \
	| LC_ALL=C sort | xargs cat | "$source_path/parse-symbols.py"
echo '#endif'
) > "$kernel_path/drivers/net/wireless/iwl7000/hdrs/mac80211-exp.h"

for fn in $(find $kernel_path/drivers/net/wireless/iwl7000/ -name '*.[ch]') ; do
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

if [ "$SIMULATION" = "1" ] ; then
  sed -i 's/#define __IWL_CHROME_CONFIG/#define __IWL_CHROME_CONFIG\n#define CPTCFG_IWLWIFI_SIMULATION 1/' \
    "$kernel_path/drivers/net/wireless/iwl7000/hdrs/config.h"
fi

if [ "$android" = "1" ] ; then
  mv -t "$kernel_path/" "$kernel_path/drivers/net/wireless/iwl7000/"*
  rm -rf "$kernel_path/drivers/"
  cp "$source_path/android/$android_build_file" "$kernel_path/BUILD.bazel"
  # remove the "pcie/*/*.c" line if we don't have those files
  if ! test -f "$kernel_path/iwlwifi/pcie/gen1_2/tx.c" ; then
    sed -i 's%pcie/\*/\*.c%%;T;d' "$kernel_path/BUILD.bazel"
  fi
  cp "$driver_path/LICENSES/preferred/GPL-2.0" "$kernel_path/LICENSE"
  # the Makefiles aren't used by the build, only BUILD.bazel, remove them
  find "$kernel_path/" -name Makefile | xargs rm
# Google didn't want the METADATA file for now
#  cp "$source_path/android/METADATA" "$kernel_path/"
#  src_hash=$(git -C $driver_path rev-parse HEAD)
#  date=$(git -C $driver_path show -s --format=%cs)
#  year=${date::4}
#  month=${date:5:2}
#  month=${month#0}
#  day=${date:8:2}
#  day=${day#0}
#  sed -i "s/<<hash>>/$src_hash/g" "$kernel_path/METADATA"
#  sed -i "s/<<year>>/$year/g" "$kernel_path/METADATA"
#  sed -i "s/<<month>>/$month/g" "$kernel_path/METADATA"
#  sed -i "s/<<day>>/$day/g" "$kernel_path/METADATA"
fi

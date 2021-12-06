#!/bin/bash
#
# Copy a given branch or commit from the input tree to the given
# output kernel tree - i.e. make a clone, prune and copy it.
#

set -e

if [ "$1" = "--simulation" ] ; then
  SIMULATION=--simulation
  shift
else
  SIMULATION=
fi

if [ -z "$1" ] || [ -z "$2" ] ; then
	echo "Please run $0 [--simulation] /path/to/iwlwifi/ /path/to/kernel/ [branch=master]"
	exit 2
fi

# must have absolute names for some git reason
driver_path="$(readlink -f "$1")"
kernel_path="$(readlink -f "$2")"
if [ -z "$3" ] ; then
	if [ "$SIMULATION" != "" ] ; then
		branch=$(git -C "$driver_path" rev-parse HEAD)
	else
		branch=master
	fi
else
	branch="$3"
fi

tmpdir=$(mktemp -d)
function finish {
	rm -rf $tmpdir
}
trap finish EXIT

cd $tmpdir
git clone "$driver_path" iwlwifi
cd iwlwifi
# handle origin/$branch or $commit
git reset --hard origin/$branch || git reset --hard $branch
cp -r intc-scripts/chromeOS/ $tmpdir
if [ "$SIMULATION" != "" ] ; then
  sed -i 's/# CPTCFG_IWLWIFI_SIMULATION is not set/CPTCFG_IWLWIFI_SIMULATION=y/' \
    defconfigs/prune-chromeos
fi
./intc-scripts/prune.py prune-chromeos
$tmpdir/chromeOS/copy-code.sh $SIMULATION $tmpdir/iwlwifi "$kernel_path"

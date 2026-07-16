#!/bin/bash
#
# Copy a given ref from the input tree to the given
# output kernel tree - i.e. make a clone, prune and copy it.
#

set -euo pipefail

if [ "${1:-}" = "--simulation" ] ; then
  SIMULATION=--simulation
  VERIFY=--noverify
  shift
else
  SIMULATION=
  VERIFY=
fi

ANDROID=
REAL_ANDROID=0
case "${1:-}" in
--android=*|--android-pre=*) # -pre is only for compat
  ANDROID="$1"
  REAL_ANDROID=1
  shift
  ;;
--aluminium)
  ANDROID="$1"
  shift
  ;;
esac

if [ -z "${1:-}" ] ; then
	echo "Please run $0 [--simulation] [--android=<name>] /path/to/kernel/ [ref]"
	echo "  (ref defaults to HEAD, i.e. use currently checked out version)"
	exit 2
fi

# must have absolute names for some git reason
driver_path="$(readlink -f "$(dirname "$0")")"
kernel_path="$(readlink -f "$1")"

cd "$driver_path"

if [ -z "${2:-}" ] || [ "$2" = "HEAD" ] ; then
	ref=$(git rev-parse HEAD)
else
	ref=$(git rev-parse "$2")
fi

tmpdir=$(mktemp -d)
function finish {
	cd $driver_path
	git worktree remove -f $tmpdir/iwlwifi
	rm -rf $tmpdir
}
trap finish EXIT

git worktree add $tmpdir/iwlwifi $ref
cd $tmpdir/iwlwifi
cp -rL intc-scripts/chromeOS/ $tmpdir
cp -r shell.nix nix/ $tmpdir
mv .git $tmpdir

# for older cores to generate android tree use master version
if [ "$REAL_ANDROID" = "1" ] && ! test -d $tmpdir/chromeOS/android/ ; then
  cp -r -t $tmpdir/chromeOS/ $driver_path/{copy-internal.sh,android}
  sed -i "s/elfutils/git elfutils/g" $tmpdir/shell.nix
fi

if [ "$SIMULATION" != "" ] ; then
  sed -i 's/# CPTCFG_IWLWIFI_SIMULATION is not set/CPTCFG_IWLWIFI_SIMULATION=y/' \
    defconfigs/prune-chromeos
fi

nix-shell --pure --run "./intc-scripts/prune.py $VERIFY prune-chromeos"
cd $tmpdir
mv $tmpdir/.git $tmpdir/iwlwifi/
nix-shell --pure --run "./chromeOS/copy-internal.sh $SIMULATION $ANDROID $tmpdir/iwlwifi \"$kernel_path\""

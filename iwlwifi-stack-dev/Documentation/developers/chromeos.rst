ChromeOS driver
===============

Overview
--------

The iwlwifi-chrome-kernel tree is updated automatically by Jenkins,
based on the iwlwifi-stack-dev tree, for every patch that goes into
the tree. Merges from upstream are done manually, see below.

As a consequence, the iwlwifi-chrome-kernel tree follows the master
and release branches, similar to the prune repositories, with the
right branch points etc. This kernel tree could be merged upstream
to preserve full history for every release (core), but that's not
how it works - see "Upstreaming process" below.

Note that we support a number of different kernels for ChromeOS that
tend to change, see the VERSIONS variable in intc-scripts/chromeos.py
for the trees and their WIFIVERSION.

In ChromeOS, our driver works against an *existing* cfg80211 version,
unlike with the usual backports where it works against a backported
cfg80211. As a consequence, changes to iwlwifi and mac80211 are done
to make them both compatible with the older cfg80211 API.

Some of these changes are done using semantic patches (spatch) while
some are (still) done using plain patches.

Fixing ChromeOS
---------------

The first step here is to analyse what kind of failure happened. In
the per-CI jenkins log, you can see whether it failed to apply the
patches or failed to compile.

Fixing patch apply process
--------------------------

The semantic patches won't usually break when applied, though with
some structural code changes might fail to apply in the right way.

The plain patches mentioned can fail to apply in two ways:

 1) pure context changes - e.g. the patch contains some code that
    you changed, but only as context
 2) changes in the code the patches change/remove

When the plain patches fail to apply, rediff them in the following way:

  0) [first time only] make sure you have "unifdef" installed, otherwise
     you might get strange errors from python

  1) Clean your local checkout of the iwlwifi-stack-dev tree to make
     sure the prune will work. Be sure not to have extra files that
     you need to keep before running this step!

     ::

         git clean -fdxq

  2) Copy the intc-scripts somewhere since they'll be deleted by
     the prune later:

     ::

         cp -a intc-scripts/ /tmp/

  3) Then run the prune script for chromeos.  This will remove all the
     stuff that is not supposed to go to the chromeos tree:

     ::

         ./intc-scripts/prune.py prune-chromeos

  4) Commit the result temporarily so that the git diff later doesn't
     include the pruning changes:

     ::

         git commit -amp

  5) Apply the iwlwifi patch (fix errors if any):

     ::

         patch -p1 < /tmp/intc-scripts/chromeOS/iwlwifi.patch

     If there are no errors, skip steps 6 through 8 (unless compilation
     failed in code affected by this patch.)

  6) To fix the compilation errors use

     ::

         #if CFG80211_VERSION >= KERNEL_VERSION(3,9,0)

     to make change the code in ways that it'll work with the cfg80211
     from the kernel version before the new feature was introduced, see
     existing code.

  7) Save the new patch:

     ::

         git diff HEAD > /tmp/intc-scripts/chromeOS/iwlwifi.patch

  8) Reset the git tree:

     ::

         git reset --hard

  9) Repeat steps 5-8 with the mac80211.patch (instead of iwlwifi.patch)

  10) Reset your tree to before the dummy patch

      ::

         git reset --hard HEAD~1

  11) Copy the iwlwifi.patch and mac80211.patch from the temporary location
      (/tmp/intc-scripts/chromeOS/) back to intc-scripts/chromeOS/ in your
      working tree and commit (--amend?) them.

Fixing compilation
------------------

Now that we use more semantic patches, compilation problems are more likely
with, for example, cfg80211 API changes.

One likely problem is using new kernel API that needs to be backported, we
add that to mac80211-bp.h and (where C functions are needed) backports.c.

Another problem that's fairly frequently encountered is when new cfg80211
API was necessary for a feature. If this just applies to net/mac80211/cfg.c
where new API functions must be stubbed out, the right file to change is
intc-scripts/chromeOS/cfgops.spatch where you can just copy/paste one of the
existing sections that stubs out e.g. "abort_scan". Make sure to update the
kernel version correctly (for the version that you'd expect the feature to
land in upstream.)

For other problems, adjust the patches or the adjustements.spatch.

Creating ChromeOS driver / compiling locally
--------------------------------------------

To compile the ChromeOS kernel locally for testing, first start with a
checkout of our "iwlwifi-chrome-kernel" from git-ger-8.devtools.intel.com:

::

  git clone ssh+git://git-ger-8.devtools.intel.com/iwlwifi-chrome-kernel
  cd iwlwifi-chrome-kernel

Use one of the "chromeos-3.x__master" or "chromeos-3.x__release/LinuxCoreXY"
branches (usually master unless you're working on a specific Core):

::

  git checkout chromeos-3.18__master

NOTE: Depending on the kernel version, you might have to set WIFIVERSION=-3.8
in the environment. If you're on a version requiring this (see the VERSIONS
variable in intc-scripts/chromeos.py) then now do:

::

  export WIFIVERSION=-3.8

(but the example here of 3.18 does *not* require it!)

Next, create any .config file that has CONFIG_IWL7000 set as a module or
built-in, for example by using

::

  ./chromeos/scripts/prepareconfig chromiumos-i386
  echo CONFIG_IWL7000=m >> .config
  yes '' | make oldconfig

Build it to see that this works OK on your system:

::

  make -j8 drivers/net/wireless$WIFIVERSION/iwl7000/

Now you can start copying your own code. To do that, have a local branch
with your changes ready, and do

::

  /path/to/iwlwifi-stack-dev/intc-scripts/chromeOS/copy.sh \
       /path/to/iwlwifi-stack-dev/ . master

replacing "master" by the branch that you're using, or a specific commit
ID if you prefer. Note that with the "." this script must be run in the
root of the ChromeOS kernel tree, and also requires WIFIVERSION= if the
kernel version requires it.

Now you can see your changes:

::

  git diff

and try to compile again:

::

  make -j8 drivers/net/wireless$WIFIVERSION/iwl7000/

To fix things, I recommend to commit these changes:

::

  git commit -amchanges

and then fix compilation as needed in the ChromeOS tree. After that's
done, you can port the changes into the iwlwifi.patch, mac80211.patch
or the modified header files (e.g. mac80211-bp.h), committing them into
stack-dev. Commit them again into ChromeOS:

::

  git commit -amfixes

and then re-apply with copy.sh

::

  /path/to/iwlwifi-stack-dev/intc-scripts/chromeOS/copy.sh \
       /path/to/iwlwifi-stack-dev/ . master

If the

::

  git diff

is empty (or at least it still compiles) you've done it correctly, if
not re-iterate and commit more changes into stack-dev until it works.


Upstreaming process
-------------------

Our driver is intended to go upstream for every Core release. The ChromeOS
maintainers agreed to merge our branches, so we just push the branches to
a separate kernel.org repository for them to merge, for core updates. Any
further small bugfixes are then applied using patches.


Merges from upstream ChromeOS repository
----------------------------------------

Merges need to be done carefully with the following caveats:

 * patches applied by Google into our driver *must* be merged into
   iwlwifi-stack-dev before merging back the upstream chromeos-x
   branch so they're not undone when the next internal patch is
   generated into the tree by the jenkins job, i.e. the order
   must be like this:

    * Google applies patch to our driver, hopefully considering our input
    * we take the same patch and apply it to iwlwifi-stack-dev
    * we may now merge upstream chromeos back into our chromeos

   Otherwise our process will cause us to drop the changes.

 * changes to support API ports or similar should be done at the
   same time as the merge, i.e. be merged into stack-dev immediately
   after the chromeos upstream merge, i.e. the process is like this:

    * prepare the fix as a gerrit patch, it should fail only on the
      kernel version(s) that got changes from Google (since the newly
      backported API isn't in our chrome repository yet)
    * disable the chromeos_generation jenkins job
    * merge the fix in gerrit
    * for the affected kernel version(s), merge origin/chromeos-x.y
      into chromeos-x.y__master in the iwlwifi-chrome-kernel repo,
      making sure to apply the fix during the merge, i.e. making the
      code in our driver exactly what's now in iwlwifi-stack-dev/master
      (could even generate that with copy.sh);
      push it into iwlwifi-chrome-kernel
    * reenable the chromeos_generation jenkins job

   (it's likely necessary to repeat this for the release branches)

   Otherwise we get some broken commits in the output tree, which is
   undesirable.

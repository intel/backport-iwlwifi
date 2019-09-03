Prune process
=============

The prune process serves to remove code we can't or don't want to publish
from the trees that go to customers. The list of trees can be found in
the trees chapter.

Process description
-------------------

The process execution happens in the intc-scripts/prune-mirror.py script,
a basic description follows:

 * For each listed branch in the input tree (here: iwlwifi-stack-dev)
   the script will check the last commit it generated in the output
   tree, by reading the "x-iwlwifi-stack-dev: <commitid>" tag in the
   commit message.
 * For each commit since that commit, it will

   - run the prune process (essentially running prune.py, but as a
     direct function call) and put the output tree's .git database
     into the pruned tree
   - if this changed anything in the pruned tree (a pure documentation
     commit for example might not) then the new state of the tree is
     committed and annotated with the "x-iwlwifi-stack-dev" tag.
   - the resulting .git database is moved to the previous location and
     the the process can start at the next commit
 * if any changes were made to the tree, the script will push the new
   state into the repository

There are special cases for when it detects

 * a new branch
   in which case it tries to find the merge-base in the input tree
   and creates the branch starting from there in the output
 * a rebased input branch
   which causes it to commit reverts backwards in history to the last
   commit that was common before and after rebase, and then apply
   starting from that point to the new commit
   (this was a special request for release/DrD_LnP_weekly_submission)


Commonly encountered problems
-----------------------------

1) "AssertionError: Wrong file: xyz"

   You added the file "xyz" to the tree, but forgot to tell the prune
   system what it should do with the file.

   If the file can always be published to all trees (the likely case,
   and the one we should strive for) then you need to simply add it to
   the list in "intc-scripts/publishable-files".

   If the file should only be published to certain defconfigs, and be
   removed for the others, then you should make sure that it's listed
   in the Makefile with the proper obj-$(CPTCFG_SYM) and that this new
   symbol CPTCFG_SYM is turned off ("CPTCFG_SYM is not set") in all
   defconfig files where it shouldn't show up. You also need to add
   the file to the list where it *may* be published, which is in the
   file "intc-scripts/publishable-files-<defconfig>". See trees.txt
   for the list of defconfig files used for which tree(s).

2) "CPTCFG_SYM state not known"

   This new symbol isn't known to the prune system yet. Make sure it's
   set properly in all the applicable defconfig files (see trees.txt)
   i.e. is either set =y or disabled ("CTPCFG_SYM is not set"). If it
   should not be enabled but still permitted in a certain or all of the
   defconfigs, add it to "intc-scripts/publishable-options-<defconfig>"
   or "intc-scripts/publishable-options" respectively.

3) Compilation failure

   This is relatively rare, but does happen if you add some code outside
   an ifdef but that's relying on other code inside an ifdef that wasn't
   set (or even removed) in the pruned build. Need to check for this and
   fix the ifdefs.

4) Kconfig flag is not present in the pruned tree

   The prune system uses the defconfig file (e.g. prune-public) not
   only to check which flags should be set by default, but also to
   remove flags and their associated code that should not be in the
   pruned tree, according to these rules:

   * If the flag is set to y ("CPTCFG_SYM=y"), it will be present in
     the pruned tree and set by default for this defconfig.  This may
     be overridden if more specific defconfigs are used when compiling
     (e.g. btns, bxt_b0 etc.);

   * If the flag is not set ("# CPTCFG_SYM is not set") the Kconfig
     option and its associated code will be *removed* from the pruned
     tree;

   * If the flag is not present in the defconfig file but is listed in
     the publishable-options file, the Kconfig option will not be
     removed and will be set to the default value defined in the
     Kconfig file for this defconfig.  Again, this may be overridden
     if other defconfig files are used during compilation.

   So, if your precious Kconfig flag has mysteriously disappeared from
   a pruned tree, check these options again.

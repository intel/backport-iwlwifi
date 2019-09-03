Writing good Commit Messages
============================

This is the (edited) text of an email I sent out a long time ago, but it
continues to be relevant for new people on the team, so having it as a
reference here is useful.

Writing good commit messages is useful for different purposes:

 * speeds up the review process - when there's a good commit message we
   can easily tell whether the patch does what it intended to, etc.
 * helps us (and new people) in the future understand why the change was
   made (and done the way it was)
 * helps people upstream understand why we’re changing the driver, to
   understand we’re not just randomly poking at things, justifying the commit
 * probably more


So what rules should you follow?

 * Avoid “git commit -m" – it makes these things harder
 * Write your commit message in the imperative: "Fix bug" and not "Fixed bug"
   or "Fixing bug". This makes more sense when reading the commit message
   before the code change, which is usually true for everyone but yourself.
   Also, it matches the convention of automated commit messages like from
   merge and revert.
 * Keep the first line (subject line) short, to the point, and prefix with the
   right things.

    * Prefix should be "iwlwifi: " or "iwlwifi: <component>: " etc.
      (obviously not for mac80211/cfg80211 changes)
      Right now we usually use the components "mvm", "dvm", "pcie" and "xvt".
    * gerrit complains after about 65 characters or so, that’s a good
      guideline, though the [BUGFIX] suffix is certainly permitted to go over
      (we strip it anyway when we send the patch upstream)
    * leave a blank line after the subject line, to separate it from the body
    * don’t end the summary line with a period (by convention)
 * For all but the simplest patches that need absolutely no explanation (this
   is rather rare) there should be a body explaining the change.

    * Don’t exceed 72 characters per line, for formatting purposes (git log,
      format-patch, etc.)
    * Multiple paragraphs, lists, etc. are perfectly fine, there’s hardly such
      a thing as a too long commit message, but avoid useless information
    * Answer the following questions:

       - Why is this change necessary?
         This tells us what to expect and also helps identify accidental
         unrelated changes.
       - How does this address the issue?
         Provide a high-level description of the solution (not a detailed code
         walk-through, we can all read the patch too)
       - What are (side) effects of this change?
         Related changes that might have been necessary, like reordering code
         etc. Try to avoid too many of these, that usually indicates a separate
         patch is better.
       - As much as possible, make the commit message understandable without
         external references, for example briefly describe the bug rather than
         just saying which one was fixed.
       - When including long links, you can use footnote-style, e.g. in the
         text say "See the spec [1]" and then after the message (in a separate
         paragraph) say "[1] http://example.com/the/spec/" (see also examples
         below). Obviously, don’t break lines inside links.
         For links to messages, using the message-ID is a good idea, e.g. if
         archived on gmane: http://mid.gmane.org/201302041844.44436.chunkeey@googlemail.com
 * Include a [BUGFIX] suffix and bug number after a --- separator for bugfixes
 * Remember that for most commits the commit message will (eventually) be
   public, so

    * Don’t use code-names ("Stone Peak")
    * Don’t refer to things we don’t want to talk about publically ("This
      breaks DBGM/WAPI/SDIO/…, because … we’ll fix it again later.") This even
      means that if you have a commit that changes multiple transports, the
      commit message should refer to PCIe only.
    * Sometimes you must obviously refer to other things, like the
      "This breaks ..." thing – do it after a "---" separator indicating that
      part should be stripped out. Make sure the commit message is consistent
      without this information.
    * This also applies to bug numbers, internal links, etc.
    * This obviously doesn’t quite apply to SDIO-only (and XVT/etc) commits
      that don’t go upstream right away, although those too might eventually
      become public so should avoid some things too

Example: The << >> angle-brackets are just highlight for what wouldn't
go upstream or into ChromeOS etc.

::

    <<[BUGFIX] >>iwlwifi: mvm: fix frozen yoghurt generation

    Due to a firmware bug, frozen yoghurt isn’t generated in frozen
    state before being passed to the host, so has to be frozen by the
    driver. Since the spec [1] requires chilling functionality already
    as outlined in a previous post [2], this isn’t difficult to do.
    However, check the temperature before chilling to avoid wasting
    energy for the extra chilling when the firmware is fixed.

    To avoid code duplication, refactor the existing chill() function
    to work with different containers, not just the round ones used
    for juice.

    [1] http://example.com/frozen-yoghurt/spec
    [2] http://mid.gmane.org/my-message-id@example.com

    <<<
    type=bugfix
    fixes=I1234567890123456789012345678901234567890
    bug=cq:MWG987654321

    Change-Id: I1234567890123456789012345678901234567891
    Signed-off-by: Johannes Berg <johannes@sipsolutions.net>
    <<<
    ---
    This also changes the XYZ (non-upstream) code to no longer use the
    chill() function, but the more appropriate cool() function instead.
    >>>

This was inspired by

 * http://linux.yyz.us/patch-format.html
 * https://github.com/erlang/otp/wiki/Writing-good-commit-messages
 * http://robots.thoughtbot.com/post/48933156625/5-useful-tips-for-a-better-commit-message
 * http://who-t.blogspot.de/2009/12/on-commit-messages.html

You can follow the
links for a more in-depth discussion of some things. Or just google "writing
good commit messages"

https://wiki.openstack.org/wiki/GitCommitMessages is also a good reference
but discusses more than just the commit message.

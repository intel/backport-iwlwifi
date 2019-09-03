Commit Message Metadata
=======================

This is only touched in passing in the chapter on commit messages, but is
important for our patch scrub/tracking, and we might also use it for
statistics later.

Each patch should be annotated with some of the following metadata:

::

 type=<type>

Where <type> is one of

 - bugfix: for bugfixes, which also then require fixes= and ticket=
 - feature: for new features or improvements
 - cleanup: code cleanups
 - maint[enance]: used only for changes to scripts, documentation,
   and similar - not for code

::

 ticket=<tracker>:<id>
 ticket=none

Where <tracker> can be "cq", "jira", "chrome-os-partner",
"chromium.org" or "kernel.org"; <id> is the bug ID in that tracker.
The string "none" is used for simple fixes or similar that were found
in development that don't have a (feature or bug) ticket associated
with them at all.

::

 fixes=<changeid>

The <changeid> should be the Change-Id of the commit that this fixes
so that the patch scrub tools can automatically determine if the fix
should be included.

All patches that fix a previous commit must have a fixes= tag,
regardless of whether they are actual bugfixes, cleanups or something
else.

We have an upstreaming script that will detect whether the original
commit was already upstreamed and handle it accordingly.  Namely, if
the commit is a bugfix and is already upstream, it will create a
"Fixes:" tag for the upstream commit message.  If not, then the script
will tag the patch for squashing and the maintainers will squash them
before sending upstream (regardless of the type=).

It is not necessary to add a [SQUASH] prefix, and not recommended
because it just pollutes the subject line.  As mentioned earlier, the
upstreaming script will decide whether the patch needs to be squashed
or not.

::

 cc=<branch>

If you know this commit is needed on a certain branch, and want to
indicate that to the patch scrub, you can put cc= (any number of
times) into the commit message, e.g. "cc=release/LinuxCore15".

For easier git log/shortlog reading, any type=bugfix must have a [BUGFIX]
prefix for the subject.

See also intc-scripts/commit-template.

If you wish to check this (along with checkpatch and the copyright checks)
locally when committing, install the "intc-scripts/post-commit" hook into
your .git directory:

::

	cd .git/hooks/
	ln -s ../../intc-scripts/post-commit .

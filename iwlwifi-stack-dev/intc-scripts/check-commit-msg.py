#!/usr/bin/env python2
#
# API to the perCI run:
# - working directory is the iwlwifi-stack-dev root
# - parameters are: <outputdir> <log-http-root> <branch>
# - return value should be bitmap of
#   * 1 -> verify=-1
#   * 2 -> code-review=-1
# - stdout is shown in the review comment
#
import sys, subprocess, os, re, time
from lib import git
from lib.copyright_checker import check_copyright

COPYRIGHT_FILE_TYPES = set(['c', 'h'])

def run_checkpatch(output_dir, http_root):
    ignore = [
        'GERRIT_CHANGE_ID',
        'BLOCK_COMMENT_STYLE',
        'NETWORKING_BLOCK_COMMENT_STYLE',
        'FILE_PATH_CHANGES',
        'SYMBOLIC_PERMS',
    ]
    p = subprocess.Popen(["git", "format-patch", "-U20", "--stdout", "HEAD~1.."],
                         stdout=subprocess.PIPE)
    c = p.communicate()[0]
    p.wait()

    # Remove the "Tested-by" line causing the checkpatch error
    c = c.replace("Tested-by: IWL Jenkins", "")

    retval = 0

    have_changeid = False
    have_sob = False
    for line in c.split('\n'):
        if line == '---':
            break
        if line.startswith('Change-Id: '):
            have_changeid = True
        if line.startswith('Signed-off-by: '):
            have_sob = True
    if not have_changeid:
        print 'Change-Id should be before ---'
        retval |= 1
    if not have_sob:
        print 'Signed-off-by should be before ---'
        retval |= 1

    p = subprocess.Popen(["./intc-scripts/checkpatch.pl", "--no-tree",
                          "--strict", "--ignore=%s" % ','.join(ignore), "-"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         stdin=subprocess.PIPE)
    stdout = p.communicate(c)[0]
    p.wait()
    f = open(os.path.join(output_dir, 'checkpatch.log'), 'w')
    f.write(stdout)
    f.close()
    if p.returncode != 0:
        print 'checkpatch failed: %scheckpatch.log' % http_root
        retval |= 2
    return retval

def check_changeid_exists(changeid):
    msg = git.log(options=['--basic-regexp', '--grep', '^Change-Id: %s$' % changeid, 'origin/master'])
    if not msg:
        return False
    return True

def check_branch_changeid():
    msg = git.commit_message("HEAD")
    changeid_re = re.compile('^Change-Id: (I[0-9a-fA-F]{40})$')
    changeid = None
    for line in msg.split('\n'):
        m = changeid_re.match(line)
        if not m:
            continue
        changeid = m.group(1)
        break
    if not changeid:
        return 0
    if not check_changeid_exists(changeid):
        print "Change-Id should exist on master"
        return 2
    return 0

def _check_type(v, req):
    """type=<bugfix|cleanup|feature|maint[enance]>"""
    types = {
        'bugfix': ['ticket', 'fixes'],
        'cleanup': [],
        'feature': [],
        'maint': [],
	'maintenance': [],
    }
    if not v in types.keys():
        print 'invalid type %s (must be one of %s)' % (
              v, ','.join(types.keys()))
        return False
    req.extend(types[v])
    return True

def _check_ticket(v, req):
    """ticket=<tracker>:<id> or 'none'"""
    trackers = {
        'cq': lambda x: x.upper().startswith('MWG100'),
        'jira': re.compile(r'^\w+-\d+$').match, # WLDTA-12345
        'chrome-os-partner': lambda x: True,
        'chromium.org': lambda x: True,
        'kernel.org': lambda x: True,
    }
    if v == 'none':
        return True
    try:
        t, b = v.split(':', 1)
    except:
        print 'malformed ticket line, must be "tracker:id" or "none"'
        return False
    t = t.lower()
    if not t in trackers:
        print 'invalid ticket tracker %s (must be one of %s), or the whole line "none"' % (
              t, ','.join(trackers))
        return False
    if not trackers[t](b):
        print 'malformed ticket ID'
        return False
    return True

def _check_cc(v, req):
    """cc=release/LinuxCoreX (can be given multiple times)"""
    try:
        git.commit_message('origin/%s' % v)
        return True
    except git.ExecutionError:
        print 'branch "%s" doesn\'t exist' % v
        return False

def _check_fixes(v, req):
    """fixes=<changeid|unknown>"""
    if v == "unknown":
        return True
    # log origin/master to avoid having a patch that fixes a previous uncommitted
    # patch that should just be squashed instead
    orig_owner = git.log(options=['--basic-regexp', '--grep', '^Change-Id: *%s$' %v , '--pretty=format:%ae', 'origin/master'])
    if not orig_owner:
        print 'fixes= change-id doesn\'t exist (yet) (or did you mean "unknown"?)'
        return False
    if 'JENKINS_HOME' in os.environ:
        subprocess.call(['ssh', 'git-amr-3.devtools.intel.com', 'gerrit','set-reviewers','-a', orig_owner, git.rev_parse('HEAD')])
    return True

def _check_restriction(v, req):
    vals = ['nopublic', 'noupstream', 'none']
    if not v in vals:
        print 'invalid value %s for restriction=, should be one of %s' % (v, ','.join(vals))
        return False
    return True

def check_internal_names():
    int_names = ['pulsar', 'windstorm', 'wsp', 'lnp' , 'lightning', 'snowfield', 'sfp', 'thunder',
		 'thp', 'lincoln', 'lcp', 'cleaveland', 'cleveland', 'cvp', 'jefferson', 'jfp', 'sandy',
		 'sdp', 'wilkins', 'wkp', 'stone', 'stp', 'lighthouse', 'lhp', 'oak', 'okp', r'(\b|_)sup(\b|_)',
                 'sunny', 'solar', 'typhoon',
		 'cherrytrail', 'cht', 'broxton', 'bxt', 'sofia', 'brtns', 'brighton', 'btns', 'phoenix', 'gsd',
		 'goldsand', 'google', 'fiber', 'asus', 'rockchip', 'quasar', 'qsr', 'icp', 'hrp', 'gfp', 'garfield']

    def remove_whitelist(line):
        whitelist = ['GFP_KERNEL', 'GFP_ATOMIC']
        for item in whitelist:
            line = line.replace(item, '')
        return line

    p = subprocess.Popen(["git", "format-patch", "--stdout", "HEAD~1.."],
                         stdout=subprocess.PIPE)
    msg_and_diff = p.communicate()[0]
    p.wait()
    msg_found = set()
    diff_found = set()
    msg = msg_and_diff.split('\n---\n')[0]
    diff = msg_and_diff.split('\ndiff --git', 1)[1]
    assert len(diff) > 0

    for line in msg.split('\n'):
        line = remove_whitelist(line)
        for n in int_names:
            m = re.search(n, line, re.IGNORECASE)
            if m:
                msg_found.add(m.group(0))
    for line in diff.split('\n'):
        if not line.startswith('+'):
            continue
        line = remove_whitelist(line)
        for n in int_names:
            m = re.search(n, line, re.IGNORECASE)
            if m:
                diff_found.add(m.group(0))
    ret = 0
    if msg_found:
        print 'Avoid mentioning %s in commit log' % (','.join(msg_found))
        ret = 1
    if diff_found:
        print 'Avoid mentioning %s in code' % (','.join(diff_found))
        ret = 1
    return ret

def check_metadata():
    msg = git.commit_message("HEAD")
    required = ['type', 'ticket']
    found = {}
    subj = msg.split('\n')[0]
    data = None
    r = 0

    for line in msg.split('\n'):
        # handle RFC 822 style folded lines
        if data and line[0].isspace():
            data += line[1:]
            continue
        else:
            data = line

        kv = data.split('=', 1)
        data = ''
        if len(kv) != 2:
            continue

        k, v = kv
        f = globals().get('_check_%s' % k, None)
        if f is None:
            # could be anything not specified since we're parsing
            # the whole commit message
            continue
        if not f(v, required):
            r |= 2
        found[k] = v

    missing = set(required) - set(found)
    m = []
    for k in missing:
        m.append("missing " + globals().get('_check_%s' % k, None).__doc__)
    if missing:
        print '\n'.join(m)
        r |= 2

    # mandate [BUGFIX] tag
    if 'type' in found and found['type'] == 'bugfix':
        if not subj.startswith('[BUGFIX]'):
            print 'bug fixes require "[BUGFIX] subject"'
            r |= 2
    else:
        # bugfix might be reverted as part of a cleanup
        if 'BUGFIX' in subj and not subj.startswith('Revert "'):
            print 'only bugfixes should have [BUGFIX] tag'
            r |= 2

    return r

if __name__ == "__main__":
    output_dir = sys.argv[1]
    http_root = sys.argv[2]
    if not http_root[-1] == '/':
        http_root += '/'
    branch = sys.argv[3]

    try:
        ret = 0
        ret |= run_checkpatch(output_dir, http_root)

        ret |= check_copyright(COPYRIGHT_FILE_TYPES)

        if branch[:8] == 'release/':
            ret |= check_branch_changeid()

        ret |= check_metadata()

	ret |= check_internal_names()

        sys.exit(ret)
    except Exception, e:
        import traceback
        traceback.print_exc()
        sys.exit(3)

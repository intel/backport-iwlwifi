#!/usr/bin/env python
'''
Monitor chromeos upstream repositories for modifications.
'''

import sys, os, smtplib
from email.mime.text import MIMEText
from lib import tempdir, git

CACHEDIR = None # use "../kernel-cache/"
SMTPSERVER = 'smtp.intel.com'
DBTREE = "ssh://git-ger-8/iwlwifi-chrome-kernel.git"
# test variables for Johannes:
#CACHEDIR = '/home/johannes/tmp/cros-cache/'
#DBTREE = "ssh://git-ger-8.devtools.intel.com/iwlwifi-chrome-kernel.git"

class Version(object):
    def __init__(self, ktree, kbranch, wifiver):
        self.ktree = ktree
        self.kbranch = kbranch
        self.wifiversion = wifiver
        self.start = None

# list the relevant chromeos trees and versions, with their WIFIVERSION
VERSIONS = [
    Version('https://chromium.googlesource.com/chromiumos/third_party/kernel', 'chromeos-3.8', ''),
    Version('https://chromium.googlesource.com/chromiumos/third_party/kernel', 'chromeos-3.14', '-3.8'),
    Version('https://chromium.googlesource.com/chromiumos/third_party/kernel', 'chromeos-3.18', ''),
    Version('https://chromium.googlesource.com/chromiumos/third_party/kernel', 'chromeos-4.4', ''),
    Version('https://chromium.googlesource.com/chromiumos/third_party/kernel', 'chromeos-4.14', ''),
    Version('https://chromium.googlesource.com/chromiumos/third_party/kernel', 'chromeos-4.19', ''),
]

def monitor_chromeos(addrs):
    cachedir = CACHEDIR
    if not cachedir:
        cachedir = os.path.join(os.getcwd(), '..', 'kernel-cache')
    if not os.path.isdir(cachedir):
        git.clone(DBTREE, cachedir, options=['--quiet', '--bare'])
    git.set_origin(DBTREE, cachedir)
    git.remote_update(cachedir)
    os.chdir(cachedir)
    db = git.commit_message('origin/monitor').split('\n')
    for line in db:
        for v in VERSIONS:
            if line.startswith(v.kbranch + ': '):
                v.start = line.split(': ')[1]
    prev = None
    tree_id = git.get_commit_var('origin/monitor', 'T')
    parent_id = git.rev_parse('origin/monitor')
    db = []
    any_changes = False
    for v in VERSIONS:
        if v.ktree != prev:
            git.set_origin(v.ktree, cachedir)
            git.remote_update(cachedir)
            prev = v.ktree
        range = 'origin/' + v.kbranch
        if v.start:
            range = v.start + '..' + range
        try:
            log = git.log([range, '--', 'drivers/net/wireless%s/iwl7000' % v.wifiversion])
        except:
            # maybe they rebased? try again w/o start
            range = 'origin/' + v.kbranch
            log = git.log([range, '--', 'drivers/net/wireless%s/iwl7000' % v.wifiversion])
        if log:
            msg = MIMEText(log)
            msg['Subject'] = 'new changes in %s' % v.kbranch
            msg['From'] = 'cros-monitor@intel.com'
            msg['To'] = ', '.join(addrs)
            s = smtplib.SMTP(SMTPSERVER)
            s.sendmail('cros-monitor@intel.com', addrs, msg.as_string())
            s.quit()
            any_changes = True
        db.append(v.kbranch + ': ' + git.rev_parse('origin/%s' % v.kbranch))
    db = ['update commit tracker', ''] + db + ['']
    msg = '\n'.join(db)

    git.set_origin(DBTREE)

    if any_changes:
        new_tree_id = git.commit_tree(tree_id, [parent_id], msg, env={
            'GIT_AUTHOR_NAME': 'cros-monitor',
            'GIT_AUTHOR_EMAIL': '',
            'GIT_COMMITTER_NAME': 'cros-monitor',
            'GIT_COMMITTER_EMAIL': '',
        })
        git.push(['origin', '%s:monitor' % new_tree_id])

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='make chromeos mirror or monitor cros trees')
    parser.add_argument('addrs', metavar='address', type=str, nargs='+', default=[],
                        help='email addresses of people to notify)')
    args = parser.parse_args()
    monitor_chromeos(args.addrs)

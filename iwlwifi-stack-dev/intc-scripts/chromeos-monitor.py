#!/usr/bin/env python3
'''
Monitor chromeos upstream repositories for modifications.
'''

import sys, os, time
from lib import git
from chromeos import VERSIONS
from jira import JIRA

COMMON_JIRA_FIELDS = {
    'project': 'WIFI',
    'issuetype': {'name': 'Task'},
    'components': [{'name': 'LinuxDriver->SMAC'}],
}
WATCHERS = ['amalamud', 'ggreenma', 'jberg1']
ASSIGNEE = 'gbenami'
PROXY = 'http://proxy.iil.intel.com:911/'

CACHEDIR = None # use "../kernel-cache/"
DBTREE = "ssh://gerritwcs.ir.intel.com:29418/iwlwifi-chrome-kernel.git"
# test variables for Johannes:
#CACHEDIR = '/home/jberg1/tmp/cros-cache/'
#DBTREE = "ssh://gerritwcs.ir.intel.com:29418/iwlwifi-chrome-kernel.git"

for v in VERSIONS:
    v.start = None
    # hmm. should it be in the other file?
    v.ktree = 'https://chromium.googlesource.com/chromiumos/third_party/kernel'

def debug(msg):
    sys.stdout.write(msg)
    sys.stdout.write('\n')
    sys.stdout.flush()

def monitor_chromeos(jira):
    n_tickets = 0
    cachedir = CACHEDIR
    if not cachedir:
        cachedir = os.path.join(os.getcwd(), '..', 'kernel-cache')
    if not os.path.isdir(cachedir):
        debug("Clone database tree to %s..." % cachedir)
        git.clone(DBTREE, cachedir, options=['--quiet', '--bare'])
    git.set_origin(DBTREE, cachedir)
    debug("Update database tree ...")
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
            debug("Update kernel tree to %s" % v.ktree)
            git.remote_update(cachedir, env={'https_proxy': PROXY})
            prev = v.ktree
        range = 'origin/' + v.kbranch
        if v.start:
            range = v.start + '..' + range
        log_args_front = ['--no-merges', '--invert-grep', '--grep=iwl7000-tree:', ]
        log_args_back = ['--', 'drivers/net/wireless/iwl7000', ]
        try:
            log = git.log(log_args_front + [range] + log_args_back)
        except:
            # maybe they rebased? try again w/o start
            range = 'origin/' + v.kbranch
            log = git.log(log_args_front + [range] + log_args_back)
        if log:
            any_changes = True
            # create a jira ticket with this info
            date = time.strftime('%Y-%m-%d')
            fields = {
                'summary': '[%s] google changed tree %s' % (v.kbranch, date),
                'description': '{noformat}\n%s\n{noformat}\n' % log,
            }
            fields.update(COMMON_JIRA_FIELDS)
            debug("creating new ticket ...")
            ticket = jira.create_issue(fields=fields)
            for watcher in WATCHERS:
                jira.add_watcher(ticket, watcher)
            jira.assign_issue(ticket, ASSIGNEE)
            debug("created ticket %s" % ticket)

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
    parser.add_argument('jira', type=str, help="JIRA API to create tickets on")
    args = parser.parse_args()

    jira_options = { 'server': args.jira, 'verify': False }
    os.environ['NO_PROXY'] = '*'
    jira_username = os.getenv('USER_JIRA')
    jira_password = os.getenv('PASS_JIRA')
    debug("Logging on to JIRA ...")
    conn = JIRA(options=jira_options, basic_auth=(jira_username, jira_password))
    monitor_chromeos(conn)

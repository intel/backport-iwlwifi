#!/usr/bin/env python

import sys
from prune import prune
from lib import git
import subprocess

def check_prune(defconfig):
    msg = git.commit_message('HEAD')

    restriction = None
    data = None
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
        if k == 'restriction':
            restriction = v
    if restriction != 'nopublic':
        return 0

    # if we want the top-most patch to have no public changes,
    # remember where we were
    commit = git.rev_parse()
    # first reset to the previous patch:
    git.reset(["-q", "--hard", "HEAD~1"])
    git.clean(['-fdxq'])
    # then prune, commit and remember the state
    prune(defconfig, False, '.')
    git.commit_all("prune test", env={
        'GIT_COMMITTER_NAME': 'prune tester',
        'GIT_COMMITTER_EMAIL': '',
        'GIT_AUTHOR_NAME': 'prune tester',
        'GIT_AUTHOR_EMAIL': '',
    })
    pruned_prev = git.rev_parse()
    # go back to the top commit
    git.reset(["-q", "--hard", commit])
    git.clean(['-fdxq'])
    # prune this one again
    prune(defconfig, False, '.')
    # reset to the previous prune
    git.reset([pruned_prev])
    # and check if anything is left:
    if git.is_modified():
        print("FAILURE: restriction=nopublic patch modifies prune tree")
        subprocess.call(['git', 'diff'])
        ret = 1
    else:
        ret = 0
    # eases development:
    git.reset(["-q", "--hard", commit])
    return ret

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='check patch pruning')
    parser.add_argument('defconfig', metavar='defconfig-file', type=str,
                        help='the defconfig file to use')
    args = parser.parse_args()

    sys.exit(check_prune(args.defconfig))

#!/usr/bin/env python
'''
mirror a tree to a pruned output tree
'''
import os
import sys
import shutil
import subprocess
from contextlib import contextmanager
import threading
import locale
from lib import git
from lib.mirror import GitMirror

# configuration
CID_PREFIX = 'x-iwlwifi-stack-dev' # don't change while tree is live
INPUT_TREE = 'ssh://git-amr-3/iwlwifi-stack-dev.git'
OUTPUT_TREE = 'ssh://git-ger-8/'
#INPUT_TREE='/home/johannes/sys/iwlwifi-stack-dev'
#OUTPUT_TREE='/tmp/'

#
# start of script
#

LOCALE_MUTEX = threading.Lock()

@contextmanager
def use_locale(name):
    with LOCALE_MUTEX:
        old = locale.setlocale(locale.LC_ALL)
        try:
            yield locale.setlocale(locale.LC_ALL, name)
        finally:
            locale.setlocale(locale.LC_ALL, old)

def prune_one(config, args):
    git_tmp = config.output_tree + '.git'
    shutil.move(os.path.join(config.output_tree, '.git'), git_tmp)
    shutil.rmtree(config.output_tree)
    shutil.copytree(config.input_tree, config.output_tree, symlinks=True,
                    ignore=shutil.ignore_patterns('.git', 'version'))
    shutil.move(git_tmp, os.path.join(config.output_tree, '.git'))

    prune_cmd = ['./intc-scripts/prune.py']
    if args.noverify:
        prune_cmd.append('--noverify')
    if args.modcompat:
        prune_cmd.append('--modcompat')
    prune_cmd.append(args.defconfig)

    try:
        subprocess.check_call(prune_cmd, cwd=config.output_tree)
    except subprocess.CalledProcessError:
        return False

    # rewrite versions file
    vfd = open(os.path.join(config.output_tree, 'versions'))
    vfl = [l for l in vfd]
    vfd.close()

    vfd = open(os.path.join(config.output_tree, 'versions'), 'w')

    for line in vfl:
        if line.startswith('BACKPORTS_GIT_TRACKED'):
            continue
        if line.startswith('BACKPORTS_BRANCH_TSTAMP'):
            continue
        vfd.write(line)

    branch_tstamp = None

    # get version/tstamp from output tree database
    obj = git.ls_tree('HEAD', files=['versions'], tree=config.output_tree)[0][2]
    version_id = 1
    for line in git.get_blob(obj, tree=config.output_tree).split('\n'):
        if line.startswith('BACKPORTS_GIT_TRACKED'):
            try:
                version_id = int(line.split(':')[2]) + 1
            except ValueError:
                pass
        if line.startswith('BACKPORTS_BRANCH_TSTAMP'):
            branch_tstamp = line[24:]

    if config.branch != 'master' and not branch_tstamp:
        if config.new_branch:
            mbase = config.start_commit
        else:
            mbase = git.merge_base(config.branch, 'origin/master', tree=config.output_tree)
        branch_tstamp = git.commit_date(mbase, tree=config.output_tree)
        with use_locale('C'):
            branch_tstamp = branch_tstamp.strftime('"%b %d %Y %H:%M:%S"')

    # keep only tree name, without ".git" (if present)
    treename = args.output_tree.split('/')[-1].split('.git')[0]
    vfd.write('BACKPORTS_GIT_TRACKED="%s:%s:%d:%s"\n' % (
        treename, config.branch, version_id, config.commit.tree_id[:8]
    ))
    if branch_tstamp:
        vfd.write('BACKPORTS_BRANCH_TSTAMP=%s\n' % branch_tstamp)
    vfd.close()

    return True

def _filter_message(msg):
    lines = []
    for line in msg.split('\n'):
        if line == '---':
            break
        lines.append(line)
    return '\n'.join(lines)

def main():
    import argparse
    parser = argparse.ArgumentParser(description='mirror into pruned git repository')
    parser.add_argument('defconfig', metavar='defconfig-file', type=str,
                        help='the defconfig file to use')
    parser.add_argument('output_tree', metavar='output-tree', type=str,
                        help='output tree name')
    parser.add_argument('branches', metavar='branch', type=str, nargs='*', default=['master'],
                        help='branches to look at (can use globbing, default: only "master")')
    parser.add_argument('--noverify', dest='noverify', action='store_const',
                        const=True, default=False,
                        help='don\'t verify the code/Kconfig')
    parser.add_argument('--modcompat', dest='modcompat', action='store_const',
                        const=True, default=False,
                        help='create module compatibility')
    args = parser.parse_args()
    mirror = GitMirror(INPUT_TREE, OUTPUT_TREE + args.output_tree,
                       args.branches,
                       lambda config: prune_one(config, args),
                       CID_PREFIX)
    mirror.is_modified = lambda tree: git.is_modified(ignore=['versions'], tree=tree)
    mirror.always_commit_new_branch = True
    mirror.git_name = 'iwlwifi publisher'
    mirror.filter_message = _filter_message
    mirror.mirror()

if __name__ == '__main__':
    main()

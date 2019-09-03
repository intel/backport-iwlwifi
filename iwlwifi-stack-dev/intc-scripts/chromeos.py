#!/usr/bin/env python
'''
Make a patch-by-patch mirror of the stack-dev tree into a ChromeOS tree
'''

import sys
import shutil
import os
import subprocess
import re
from lib.mirror import GitMirror, Abort
from lib.tempdir import Tempdir
from lib import git

# configuration (the first few lines are local ones)
INPUT_TREE = "ssh://git-amr-3/iwlwifi-stack-dev.git"
OUTPUT_TREE = "ssh://git-ger-8/iwlwifi-chrome-kernel.git"
#INPUT_TREE = '/tmp/iwlwifi-stack-dev.git'
#OUTPUT_TREE = '/home/johannes/tmp/chrome-kernel.git'
#INPUT_TREE = '/home/luca/iwlwifi/stack-dev/'
#OUTPUT_TREE = '/tmp/chromeos/chrome-kernel/'
DEFCONFIGS = ["prune-chromeos"]

class Version(object):
    """
    Version container object
    """
    def __init__(self, kbranch, branches=['release/core[4-9]*'], wifiver=''):
        self.kbranch = kbranch
        self.wifiversion = wifiver
        self.branches = branches[:]

# list the relevant chromeos versions, with their WIFIVERSION
VERSIONS = [
    Version('chromeos-3.8',),
    Version('chromeos-3.14', wifiver='-3.8'),
    Version('chromeos-3.18'),
    Version('chromeos-4.4'),
    Version('chromeos-4.14'),
    Version('chromeos-4.19'),
]

def _create_chrome_driver(config, version):
    with Tempdir() as scratch_root:
        scripts_dir = os.path.join(scratch_root, 'scripts')

        # make a copy of the scripts - we're going to delete them next
        shutil.copytree(os.path.join(config.input_tree, 'intc-scripts', 'chromeOS'), scripts_dir)

        # prune the original
        defconfig = None
        for defc in DEFCONFIGS:
            defc_file = os.path.join(config.input_tree, "defconfigs", defc)
            if os.access(defc_file, os.R_OK):
                defconfig = defc
                sys.stdout.write("using defconfig file '%s'\n" % defc)
                sys.stdout.flush()
                break
        if defconfig is None:
            sys.stdout.write('cannot find defconfig, fix the script. aborting!\n')
            sys.stdout.flush()
            raise Abort()
        prune = subprocess.Popen(["./intc-scripts/prune.py", defconfig],
                                 cwd=config.input_tree)
        prune.wait()
        if prune.returncode != 0:
            sys.stdout.write('^^^^ prune FAILED for commit %s\n' % config.commit.tree_id)
            sys.stdout.flush()
            return False

        # copy as iwl7000 driver to outdir
        env = os.environ.copy()
        if version.wifiversion:
            env['WIFIVERSION'] = version.wifiversion
        null = open('/dev/null', 'r')
        copy = subprocess.Popen(['./copy-code.sh', config.input_tree, config.output_tree],
                                cwd=scripts_dir, env=env, stdin=null,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout = copy.communicate()[0]
        copy.wait()
        if copy.returncode != 0:
            sys.stdout.write('/------ FAILED for commit %s\n' % config.commit.tree_id)
            for line in stdout.split('\n'):
                sys.stdout.write('| ')
                sys.stdout.write(line)
                sys.stdout.write('\n')
            sys.stdout.write('\\------\n')
            sys.stdout.flush()
            return False

    return True

def _filter_message(msg):
    # - remove things after ---
    lines = msg.split('\n')
    subj = lines[0]
    out_lines = []
    for line in lines[1:]:
        if line == '---':
            break
        out_lines.append(line)
    lines = out_lines

    # - give it an appropriate prefix
    subj = subj.strip()
    subj = re.sub(r'\s*\[[^\]\[]*\]\s*', '', subj)
    subj = re.sub(r'^iwlwifi:\s*', '', subj)
    subj = 'CHROMIUM: iwl7000: ' + subj

    # - remove our metadata
    # TODO: could translate to BUG= for chrome-os-partner:123456
    nlines = []
    prev = None
    for line in lines:
        meta = ['type', 'fixes', 'cc', 'bug', 'jira', 'ticket', 'hw']
        ismeta = False
        for mkey in meta:
            if line.lower().startswith(mkey + '='):
                ismeta = True
                break
        if ismeta:
            continue

        # remove extra tags
        gerrit = [
            'reviewed-on',
            'tested-by',
            'reviewed-by',
            'automatic-review',
        ]
        isgerrit = False
        for tag in gerrit:
            if line.lower().startswith(tag + ': '):
                isgerrit = True
                break
        if isgerrit:
            continue

        if prev == '' and line == '':
            continue
        prev = line
        nlines.append(line)

    msg = '\n'.join(nlines)

    # make sure there's anything, and a trailing \n
    if not msg:
        msg = '\n'
    if msg[-1] != '\n':
        msg += '\n'

    # add the subject back to the message
    return subj + '\n' + msg

def main():
    """
    main function of the script
    """
    import argparse
    parser = argparse.ArgumentParser(description='make chromeos mirror')
    parser.add_argument('branches', metavar='branch', type=str, nargs='*',
                        help='deprecated')
    args = parser.parse_args()

    if args.branches:
        sys.stdout.write('passing branches in the command line is deprecated and now ignored.\n')
        sys.stdout.write('the branches for each kernel version are now hardcoded in the script.\n')

    success = True

    with Tempdir() as tmpdir:
        output_tree_copy = os.path.join(tmpdir, 'out-pull')
        input_tree_copy = os.path.join(tmpdir, 'input')
        sys.stdout.write('Cloning input tree\n')
        sys.stdout.flush()
        git.clone(INPUT_TREE, input_tree_copy, options=['-q', '--mirror'])
        sys.stdout.write('Cloning output tree\n')
        sys.stdout.flush()
        git.clone(OUTPUT_TREE, output_tree_copy, options=['-q', '--mirror'])

        for version in VERSIONS:
            mirror = GitMirror(input_tree_copy, OUTPUT_TREE, version.branches,
                               lambda config, ver=version: _create_chrome_driver(config, ver),
                               'iwl7000-tree')
            mirror.output_branch_name = lambda x, ver=version: '%s__%s' % (ver.kbranch, x)
            mirror.git_name = 'Intel ChromeOS bot'
            mirror.git_email = 'linuxwifi@intel.com'
            mirror.clean_output = False
            mirror.filter_message = _filter_message
            mirror.output_tree_pull = output_tree_copy
            mirror.debug('=========== working on %s' % version.kbranch)
            if not mirror.mirror():
                success = False

    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
'''
Make a patch-by-patch mirror of the stack-dev tree into an Android tree
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
INPUT_TREE = "ssh://gerritwcs.ir.intel.com:29418/iwlwifi-stack-dev.git"
OUTPUT_TREE = "ssh://gerritwcs.ir.intel.com:29418/iwlwifi-stack-android.git"
#INPUT_TREE = os.path.expanduser('~/iwlwifi-stack-dev')
#OUTPUT_TREE = '/tmp/iwlwifi-android.git'
DEFCONFIGS = ["prune-chromeos"]

MAIN_TREE = os.path.join(os.path.dirname(__file__), '..')

class Version(object):
    """
    Version container object
    """
    def __init__(self, kbranch, version, branches=['release/core9[6-9]*', 'release/core[1-9][0-9][0-9]*']):
        self.kbranch = kbranch
        self.version = version
        self.branches = branches[:]

# list the relevant android versions
VERSIONS = [
    Version('android16-6.12-desktop', 'google'),
    # naming scheme will probably change before core 109
    Version('android17-6.18-desktop', 'google618', branches=['release/core10[3-9]*']),
]

def _create_android_driver(config, version, outer_nix):
    with Tempdir() as scratch_root:
        scripts_dir = os.path.join(scratch_root, 'scripts')
        nix_dir = os.path.join(scratch_root, 'nix')

        # make a copy of the scripts - we're going to delete them next
        shutil.copytree(os.path.join(config.input_tree, 'intc-scripts', 'chromeOS'),
                        scripts_dir, symlinks=False)

        # copy all the nix dependencies if used
        shutil.copytree(os.path.join(config.input_tree, 'nix'), nix_dir)
        shutil.copy(os.path.join(config.input_tree, 'shell.nix'), scratch_root)
        def nix_run(args):
            ret = ['nix-shell', '--pure', '--run']
            ret.append(' '.join(args))
            return ret

        # core release branch prior to the change adding real support
        # can use - as an exception - the one that shipped later
        if not os.path.exists(os.path.join(config.input_tree, 'intc-scripts', 'chromeOS', 'android', 'BUILD.bazel')):
            shutil.copy(os.path.join(MAIN_TREE, 'intc-scripts', 'chromeOS', 'copy-internal.sh'),
                        scripts_dir)
            shutil.copy(os.path.join(MAIN_TREE, 'intc-scripts', 'chromeOS', 'android.yaml'),
                        scripts_dir)
            if os.path.exists(os.path.join(scripts_dir, 'android')):
                shutil.rmtree(os.path.join(scripts_dir, 'android'))
            shutil.copytree(os.path.join(MAIN_TREE, 'intc-scripts', 'chromeOS', 'android'),
                            os.path.join(scripts_dir, 'android'))
            nix_shell = os.path.join(scratch_root, 'shell.nix')
            with open(nix_shell, 'rb') as sh:
                data = sh.read()
            data = data.replace(b'elfutils', b'yq git elfutils')
            with open(nix_shell, 'wb') as sh:
                sh.write(data)

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
        prune = subprocess.Popen(nix_run(['./intc-scripts/prune.py', defconfig]),
                                 cwd=config.input_tree)
        prune.wait()
        if prune.returncode != 0:
            sys.stdout.write('^^^^ prune FAILED for commit %s\n' % config.commit.tree_id)
            sys.stdout.flush()
            return False

        # copy as iwl7000 driver to outdir
        env = os.environ.copy()
        null = open('/dev/null', 'r')
        copy = subprocess.Popen(nix_run(['./scripts/copy-internal.sh',
                                         f'--android={version.version}',
                                         config.input_tree, config.output_tree]),
                                cwd=scratch_root, env=env, stdin=null,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
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
    subj = re.sub(r'^wifi:\s*', '', subj)
    subj = re.sub(r'^iwlwifi:\s*', '', subj)
    subj = re.sub(r'^chromeOS:\s*', '', subj, flags=re.IGNORECASE)
    subj = re.sub(r'^android:\s*', '', subj, flags=re.IGNORECASE)
    subj = 'ANDROID: iwl7000: ' + subj

    # - remove our metadata
    # TODO: could translate to BUG= for chrome-os-partner:123456
    nlines = []
    prev = None
    for line in lines:
        meta = ['type', 'fixes', 'cc', 'bug', 'jira', 'ticket', 'hw', 'origin']
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
            'perci-ready',
            'tested',
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
    parser = argparse.ArgumentParser(description='make android mirror')
    parser.add_argument('branches', metavar='branch', type=str, nargs='*',
                        help='deprecated')
    args = parser.parse_args()

    if args.branches:
        sys.stdout.write('passing branches in the command line is deprecated and now ignored.\n')
        sys.stdout.write('the branches for each kernel version are now hardcoded in the script.\n')

    success = True

    outer_nix = os.path.join(os.getcwd(), 'shell.nix')

    with Tempdir() as tmpdir:
        output_tree_copy = os.path.join(tmpdir, 'out-pull')
        input_tree_copy = os.path.join(tmpdir, 'input')
        sys.stdout.write('Cloning input tree\n')
        sys.stdout.flush()
        git.clone(INPUT_TREE, input_tree_copy,
                  options=['-q', '--mirror', f'--reference={MAIN_TREE}'])
        sys.stdout.write('Cloning output tree\n')
        sys.stdout.flush()
        git.clone(OUTPUT_TREE, output_tree_copy, options=['-q', '--mirror'])

        for version in VERSIONS:
            mirror = GitMirror(input_tree_copy, OUTPUT_TREE, version.branches,
                               lambda config, ver=version: _create_android_driver(config, ver,
                                                                                  outer_nix),
                               'iwl7000-tree')
            mirror.output_branch_name = lambda x, ver=version: '%s__%s' % (ver.kbranch, x)
            mirror.git_name = 'Intel Android bot'
            mirror.git_email = 'linuxwifi@intel.com'
            mirror.clean_output = False
            mirror.filter_message = _filter_message
            mirror.output_tree_pull = output_tree_copy
            mirror.is_modified = lambda tree: git.is_modified(ignore=['METADATA'], tree=tree)
            mirror.debug('=========== working on %s' % version.kbranch)
            if not mirror.mirror():
                success = False

    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()

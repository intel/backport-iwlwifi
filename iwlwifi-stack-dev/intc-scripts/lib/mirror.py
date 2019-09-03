#
# INTEL CONFIDENTIAL
#
# Copyright (C) 2018 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials, and
# your use of them is governed by the express license under which they were
# provided to you (License). Unless the License provides otherwise, you may not
# use, modify, copy, publish, distribute, disclose or transmit this software or
# the related documents without Intel's prior written permission.
#
# This software and the related documents are provided as is, with no express or
# implied warranties, other than those that are expressly stated in the License.
#
"""
This implements a helper class for mirroring branch(es) of one git repository
to another, while modifying them along the way.
"""
import sys
import os
import re
import shutil
from collections import OrderedDict
import tempdir
import git

class Abort(Exception):
    """
    Exception indicating the modify method went so bad that
    the whole process should be stopped
    """
    pass

def _default_debug(line):
    sys.stdout.write(line)
    sys.stdout.write('\n')
    sys.stdout.flush()

class Config(object):
    """
    Configuration object passed to modify method.
    """
    def __init__(self, commit, branch, start_commit, new_branch,
                 input_tree, output_tree):
        self.commit = commit
        self.branch = branch
        self.start_commit = start_commit
        self.new_branch = new_branch
        self.input_tree = input_tree
        self.output_tree = output_tree

class Commit(object):
    """
    Represents a commit while processing, with the commit ID
    of the tree the output should be generated from, the commit
    ID of the message to use, and whether or not it's a revert.
    """
    def __init__(self, commit_id, tree, revert=False):
        self._msg_id = commit_id
        if revert:
            self._tree_id = git.rev_parse('%s~1' % commit_id, tree=tree)
        else:
            self._tree_id = git.rev_parse('%s' % commit_id, tree=tree)
        self._revert = revert
        self._tree = tree
    def __repr__(self):
        subj = git.commit_message(self._tree_id, tree=self._tree).split('\n')[0]
        return '<Commit(tree=%s,id=%s,subj=%s)>' % (self._tree, self._tree_id, subj)
    @property
    def tree_id(self):
        """
        return the tree's commit ID to generate from
        """
        return self._tree_id
    @property
    def msg_id(self):
        """
        return the commit ID to use for the message
        """
        return self._msg_id
    @property
    def revert(self):
        """
        return whether or not this is a revert
        """
        return self._revert

class GitMirror(object):
    """
    Mirror one git tree to another, given the branches and method to modify it.
    """
    def __init__(self, input_tree, output_tree, branches, modify, cid_prefix):
        self._input_tree = input_tree
        self._output_tree = output_tree
        self._branches = branches
        self._modify = modify
        self._commit_id_prefix = cid_prefix
        self._id_re = re.compile(cid_prefix + ': ([0-9a-fA-F]*)')

        # allowed to change these externally
        self.is_modified = git.is_modified
        self.debug = _default_debug
        self.master = 'master'
        self.max_parents = 100
        self.always_commit_new_branch = False
        self.git_name = 'mirror script'
        self.git_email = ''
        self.clean_output = True
        self.reference = ['--reference', os.getcwd()]
        self.output_branch_name = lambda name: name
        self.filter_message = lambda msg: msg
        self.notes_branch = 'mirror'
        self.output_tree_pull = None

    def _glob_branches(self, input_work_dir):
        globbed = [self.master]
        for branch in self._branches:
            globbed.extend(git.list_branches(branch, tree=input_work_dir))
        return list(OrderedDict.fromkeys(globbed))

    def _check_new_branch(self, branch, input_work_dir, output_work_dir, output_reference):
        # try to find merge-base in input tree,
        # assumes master branch is always mirrored
        #
        # this handles the case of having created a new branch,
        # and asking for that to be mirrored into the prune tree.
        base_id = git.merge_base('origin/' + self.master, 'origin/' + branch, tree=input_work_dir)
        git.clone(output_reference, output_work_dir, options=['-q'])
        git.set_origin_url(self._output_tree, output_work_dir)

        # try to find the merge-base or its parent/grandparent/... in the
        # output tree - since it should have been branched from the master
        # (or in any case we look at the merge-base between master and it)
        # this should exist - HOWEVER: some commits might not be mirrored,
        # so look for the *parent [with a reasonable limit]
        for offset in range(0, self.max_parents):
            search = git.rev_parse(rev='%s~%d' % (base_id, offset), tree=input_work_dir)
            self.debug('search for %s~%d=%s:' % (base_id, offset, search))
            grep = '%s: %s' % (self._commit_id_prefix, search)
            out_commits = git.log(options=['--grep', grep, '--format=format:%H',
                                           'origin/' + self.output_branch_name(self.master)],
                                  tree=output_work_dir)
            out_commits = out_commits.split()
            if not out_commits or len(out_commits) > 1:
                self.debug('not found')
                continue
            start_commit = out_commits[0]
            self.debug('found at %s' % start_commit)
            return start_commit
        raise Exception('failed to find parent/grandparent/...')

    def _log_commits(self, from_ref, to_ref, tree_dir):
        new_commits = git.log_commits(from_ref, to_ref, tree=tree_dir)
        dropped_commits = git.log_commits(to_ref, from_ref, tree=tree_dir)
        # if there are dropped commits the input branch was rebased over what
        # we had already mirrored before - this is explicitly done to handle
        # rebased branches, but we keep the output linear in that case
        if dropped_commits:
            dropped_commits.reverse()
            dropped_commits = [Commit(x, tree_dir,
                                      revert=True) for x in dropped_commits]
        return dropped_commits + [Commit(x, tree_dir) for x in new_commits]

    def _find_commits(self, branch, start_commit, input_work_dir, output_work_dir):
        # If somebody manually modified the output tree without pointing to an
        # input tree commit (which really should happen only in the case of
        # ChromeOS where we may merge upstream) then search for the original
        # commit pointer also in the parent, etc. of the top-most output commit.
        last_commit = None

        for back in range(self.max_parents):
            last_commit = git.get_note(self.notes_branch, '%s~%d' % (start_commit, back), tree=output_work_dir)
            if last_commit is not None:
                last_commit = last_commit.strip()
                self.debug('Found note on %s~%d indicating last checked commit is %s' % (
                           start_commit, back, last_commit))
                break

            try:
                msg = git.commit_message('%s~%d' % (start_commit, back), tree=output_work_dir)
            except git.GitError:
                msg = ''
            match = self._id_re.search(msg)
            if match:
                last_commit = match.group(1)
                break

        if last_commit:
            return self._log_commits(last_commit, 'origin/' + branch, input_work_dir)

        # Note that this is also important if working on a new branch, where
        # we get here through self._need_to_mirror() with start_commit being
        # just the branch name - so above we'll have tried something like
        # new_branch~0, new_branch~1 etc. none of which can exists. So now
        # this will give up and tell us to create just the single commit,
        # which at least is some work to do so we can sort it out later in
        # self._prepare_output_git() which detects and bases a new branch
        # properly.
        commit_id = git.rev_parse('origin/' + branch, tree=input_work_dir)
        return [Commit(commit_id, input_work_dir)]

    def _prepare_output_git(self, branch, input_work_dir, output_work_dir, output_reference):
        start_commit = self.output_branch_name(branch)
        new_branch = False
        try:
            git.clone(output_reference, output_work_dir,
                      options=['--branch', self.output_branch_name(branch), '-q'])
            git.set_origin_url(self._output_tree, output_work_dir)
            try:
                git.commit_env_vars(self.output_branch_name(branch), tree=output_work_dir)
            except git.GitError:
                shutil.rmtree(output_work_dir)
                self.debug('clone incorrect - new branch?')
                raise Exception('clone incorrect - new branch?')
        except:
            # assume error was due to branch not found
            new_branch = True
            start_commit = self._check_new_branch(branch, input_work_dir, output_work_dir,
                                                  output_reference)
            git.reset(['--hard', start_commit], tree=output_work_dir)

        try:
            git.fetch('refs/notes/mirror:refs/notes/mirror', tree=output_work_dir)
        except:
            pass

        return start_commit, new_branch

    def _commit(self, commit, msg, env, output_work_dir, tree_id=None, parents=None, add_id=True):
        msg = self.filter_message(msg)
        if add_id:
            msg += '%s: %s' % (self._commit_id_prefix, commit.tree_id)
        if tree_id:
            assert parents is not None
            new_commit = git.commit_tree(tree_id, parents, msg, tree=output_work_dir, env=env)
            git.reset(opts=['--hard', new_commit], tree=output_work_dir)
        else:
            assert parents is None
            git.commit(msg, env=env, opts=['-a', '-q'], tree=output_work_dir)

    def _commit_modified(self, commit, input_work_dir, output_work_dir,
                         last_failure_shortlog, tree_id=None, parents=None, add_id=True):
        if commit.revert or last_failure_shortlog:
            env = {
                'GIT_COMMITTER_NAME': self.git_name,
                'GIT_COMMITTER_EMAIL': self.git_email,
                'GIT_AUTHOR_NAME': self.git_name,
                'GIT_AUTHOR_EMAIL': self.git_email,
            }
        else:
            env = git.commit_env_vars(commit.tree_id, tree=input_work_dir)
            env.update({
                'GIT_COMMITTER_NAME': self.git_name,
                'GIT_COMMITTER_EMAIL': self.git_email,
            })
        if commit.revert:
            msg = git.commit_message(commit.msg_id, tree=input_work_dir)
            subj = msg.split('\n')[0]
            msg = 'Revert "%s"\n\n' % subj
            msg += 'This commit was rebased out so revert it here.'
        elif last_failure_shortlog:
            msg = 'mirror: multi-input commit\n\n'
            msg += 'Some commits failed to generate and were skipped. This commit\n'
            msg += 'is a combination of them, with the following original commits:\n\n'
            msg += last_failure_shortlog
        else:
            msg = git.commit_message(commit.msg_id, tree=input_work_dir)
        if msg[-1] != '\n':
            msg += '\n'
        self._commit(commit, msg, env, output_work_dir, tree_id, parents, add_id)

    def _commit_env(self):
        env = {
            'GIT_COMMITTER_NAME': self.git_name,
            'GIT_COMMITTER_EMAIL': self.git_email,
            'GIT_AUTHOR_NAME': self.git_name,
            'GIT_AUTHOR_EMAIL': self.git_email,
        }
        return env

    def _commit_new_branch(self, commit, output_work_dir):
        msg = 'mirror: new branch created\n\n'
        self._commit(commit, msg, self._commit_env(), output_work_dir)

    @classmethod
    def _clean_output_dir(cls, output_work_dir):
        for root, dirs, files in os.walk(output_work_dir):
            for dname in dirs:
                if dname == '.git':
                    continue
                shutil.rmtree(os.path.join(root, dname))
            for fname in files:
                os.remove(os.path.join(root, fname))
            break

    def _need_to_mirror(self, branch, input_work_dir, output_reference):
        commits = self._find_commits(branch, self.output_branch_name(branch),
                                     input_work_dir, output_reference)
        return len(commits) > 0

    def _checkout(self, commit, input_work_dir):
        git.reset(opts=['--hard', commit], tree=input_work_dir)
        git.clean(opts=['-fdxq'], tree=input_work_dir)
        git.submodule(['--quiet', 'sync'], tree=input_work_dir)
        git.submodule(['--quiet', 'update'], tree=input_work_dir)
        git.submodule(['--quiet', 'foreach', 'git', 'reset', '-q', '--hard'], tree=input_work_dir)
        git.submodule(['--quiet', 'foreach', 'git', 'clean', '-fdxq'], tree=input_work_dir)

    def _submodule_status(self, input_work_dir):
        result = git.submodule_status(tree=input_work_dir)
        ret = {}
        for r in result:
            assert r[0] == ' '
            ret[r[2]] = r[1]
        return ret

    def _create_output(self, branch, commit, input_work_dir, output_work_dir, start_commit, new_branch,
                       submodules=None):
        # get a fresh work tree (local clone)
        self._checkout(commit.tree_id, input_work_dir)
        if submodules:
            for submodule, submodule_commit in submodules.iteritems():
                self._checkout(submodule_commit.tree_id, os.path.join(input_work_dir, submodule))

        if self.clean_output:
            self._clean_output_dir(output_work_dir)

        config = Config(commit, branch, start_commit, new_branch,
                        input_work_dir, output_work_dir)

        return self._modify(config)


    def _handle_submodule(self, branch, outer_commit, submodule_path, prev_commit, cur_commit,
                          input_work_dir, output_work_dir, start_commit, new_branch):
        submodule_tree = os.path.join(input_work_dir, submodule_path)
        commits = self._log_commits(prev_commit, cur_commit, submodule_tree)
        for commit in commits:
            # ok ... if any fails just abandon the whole thing - could be better, but ...
            if not self._create_output(branch, outer_commit, input_work_dir, output_work_dir,
                                       start_commit, new_branch,
                                       submodules={submodule_path: commit}):
                return []
            git.add('.', tree=output_work_dir)

            if self.is_modified(tree=output_work_dir):
                self._commit_modified(commit, submodule_tree, output_work_dir, None, add_id=False)
        return [git.rev_parse('HEAD', tree=output_work_dir)]

    def _mirror_one(self, branch, input_work_dir, output_reference):
        self.debug('*********** start work for branch %s -> %s' % (
            branch,
            self.output_branch_name(branch),
        ))

        if not self._need_to_mirror(branch, input_work_dir, output_reference):
            return True

        with tempdir.tempdir() as tmpdir:
            output_work_dir = os.path.join(tmpdir, 'output')
            start_commit, new_branch = self._prepare_output_git(branch, input_work_dir,
                                                                output_work_dir,
                                                                output_reference)

            commits = self._find_commits(branch, start_commit, input_work_dir, output_work_dir)

            os.chdir(tmpdir)

            committed_anything = False

            last_failure = None

            try:
                # In this case we're already done, the loop below would be skipped
                # completely, but we can't even calculate the (unnecessary)
                # prep_prev_commit and similar, nor do we really have to check out
                # the code to generate nothing. However, if it's a new branch we
                # may have to push it out, so go through the "finally:" segment of
                # the code (and hence have the return statement within the "try:"
                # block.
                # The output tree is correct since self._prepare_output_git() will
                # leave it at the commit it wanted to start generating from (even
                # if there's nothing to generate, it doesn't consider that.)
                if len(commits) == 0:
                    return True

                prep_prev_commit = Commit(git.rev_parse(commits[0].tree_id + '^', tree=input_work_dir),
                                          input_work_dir)
                self._checkout(prep_prev_commit.tree_id, input_work_dir)
                submodules = self._submodule_status(input_work_dir)

                for commit in commits:
                    prev_commit = prep_prev_commit
                    prep_prev_commit = commit
                    if not self._create_output(branch, commit, input_work_dir, output_work_dir,
                                               start_commit, new_branch):
                        if last_failure is None:
                            last_failure = commit
                        continue

                    if last_failure:
                        last_failure_shortlog = git.shortlog(last_failure, commit)
                    else:
                        last_failure_shortlog = None

                    git.add('.', tree=output_work_dir)

                    prev_submodules = submodules
                    submodules = self._submodule_status(input_work_dir)

                    if self.is_modified(tree=output_work_dir):
                        parents = [git.rev_parse('HEAD', tree=output_work_dir)]
                        tree_id = git.write_tree(tree=output_work_dir)
                        for s in submodules:
                            if not s in prev_submodules:
                                continue
                            if prev_submodules[s] != submodules[s]:
                                parents += self._handle_submodule(branch, prev_commit,
                                                                  s, prev_submodules[s],
                                                                  submodules[s],
                                                                  input_work_dir,
                                                                  output_work_dir,
                                                                  start_commit,
                                                                  new_branch)
                        self._commit_modified(commit, input_work_dir, output_work_dir,
                                              last_failure_shortlog, tree_id, parents)
                        committed_anything = True
                    elif new_branch and self.always_commit_new_branch:
                        self._commit_new_branch(commit, output_work_dir)
                        committed_anything = True
                        new_branch = False

                    last_failure = None
                    git.set_note(self.notes_branch, 'HEAD', commit.tree_id, tree=output_work_dir,
                                 env=self._commit_env())
            except Abort:
                return False
            finally:
                # if necessary, push to the server from the output_work_dir
                git.set_origin_url(self._output_tree, gitdir=output_work_dir)
                if committed_anything or new_branch:
                    git.push(opts=['-q', 'origin', 'HEAD:' + self.output_branch_name(branch)],
                             tree=output_work_dir)
                git.push(opts=['-q', '-f', 'origin', 'refs/notes/' + self.notes_branch],
                         tree=output_work_dir)

            return True

    def mirror(self):
        """
        Start the mirroring process according to the configuration.
        """
        cwd = os.getcwd()
        result = True
        with tempdir.tempdir() as tmpdir:
            input_work_dir = os.path.join(tmpdir, 'input')

            git.clone(self._input_tree, input_work_dir, options=self.reference + ['-q'])
            git.remote_update(gitdir=input_work_dir)
            git.submodule(['--quiet', 'init'], tree=input_work_dir)
            git.submodule(['--quiet', 'sync'], tree=input_work_dir)
            git.submodule(['--quiet', 'update'], tree=input_work_dir)

            if self.output_tree_pull:
                output_reference = self.output_tree_pull
            else:
                output_reference = os.path.join(tmpdir, 'outref')
                git.clone(self._output_tree, output_reference, options=['-q', '--mirror'])

            _branches = self._glob_branches(input_work_dir)

            for branch in _branches:
                try:
                    if not self._mirror_one(branch, input_work_dir, output_reference):
                        result = False
                finally:
                    os.chdir(cwd)
        return result

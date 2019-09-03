#
# INTEL CONFIDENTIAL
#
# Copyright (C) 2017 Intel Deutschland GmbH
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

import subprocess, re, tempfile

class GitError(Exception):
    pass
class SHAError(GitError):
    pass
class ExecutionError(GitError):
    def __init__(self, errcode):
        GitError.__init__(self)
        self._error_code = errcode
    def __str__(self):
        return "ExecutionError: %d" % self._error_code

def _check(process, stderr=None):
    if process.returncode != 0:
        raise ExecutionError(process.returncode)

_sha_re = re.compile('^[0-9a-fA-F]*$')

def rev_parse(rev='HEAD', tree=None):
    process = subprocess.Popen(['git', 'rev-parse', rev],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)

    sha = stdout.strip()
    if not _sha_re.match(sha):
        raise SHAError()
    return sha

def describe(rev='HEAD', tree=None):
    process = subprocess.Popen(['git', 'describe', '--always', '--long', rev],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)

    return stdout.strip()

def init(tree=None, options=[]):
    process = subprocess.Popen(['git', 'init'] + options,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)

def add(fn, tree=None):
    process = subprocess.Popen(['git', 'add', '--all', fn], cwd=tree,
                               close_fds=True, universal_newlines=True)
    process.wait()
    _check(process)

def commit_all(message, tree=None, env={}):
    add('.', tree=tree)
    process = subprocess.Popen(['git', 'commit', '--allow-empty', '-a', '-m', message],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree, env=env)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)

def get_commit_var(commit, var, tree=None):
    process = subprocess.Popen(['git', 'show', '--name-only',
                                '--format=%%%s%%x00' % var, commit],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    return stdout.split('\x00')[0]

def commit_tree(parent, message, tree, cwd=None, env={}):
    if parent is None:
        parent = []
    else:
        parent = ['-p', parent]
    process = subprocess.Popen(['git', 'commit-tree', '-F', '-', tree] + parent,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               cwd=cwd, env=env)
    stdout = process.communicate(message)[0]
    process.wait()
    _check(process)
    return stdout.strip()

def ls_tree(rev, files, tree=None):
    process = subprocess.Popen(['git', 'ls-tree', '-z', '-r', rev, '--', ] + list(files),
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    files = stdout.split('\0')
    ret = []
    for f in files:
        if not f:
            continue
        meta, f = f.split('\t', 1)
        meta = meta.split()
        meta.append(f)
        ret.append(meta)
    process.wait()
    _check(process)
    return ret

def get_blob(blob, outf=None, tree=None):
    pipe = False
    ret = None
    if outf is None:
        outf = subprocess.PIPE
        pipe = True
    process = subprocess.Popen(['git', 'show', blob],
                               stdout=outf, close_fds=True, cwd=tree)
    if pipe:
        ret = process.communicate()[0]
    process.wait()
    _check(process)
    return ret

def clone(gittree, outputdir, options=[], env=None):
    process = subprocess.Popen(['git', 'clone'] + options + [gittree, outputdir],
                               env=env)
    process.wait()
    _check(process)

def set_origin(giturl, gitdir=None):
    process = subprocess.Popen(['git', 'remote', 'rm', 'origin'],
                               close_fds=True, universal_newlines=True, cwd=gitdir)
    process.wait()

    process = subprocess.Popen(['git', 'remote', 'add', 'origin', giturl],
                               close_fds=True, universal_newlines=True, cwd=gitdir)
    process.wait()
    _check(process)

def set_origin_url(giturl, gitdir=None):
    process = subprocess.Popen(['git', 'remote', 'set-url', 'origin', giturl],
                               close_fds=True, universal_newlines=True, cwd=gitdir)
    process.wait()
    _check(process)

def add_remote(name, giturl, gitdir='.'):
    process = subprocess.Popen(['git', 'remote', 'add', name, giturl],
                               close_fds=True, universal_newlines=True, cwd=gitdir)
    process.wait()
    _check(process)

def remote_update(gitdir=None, remote=None, env=None):
    args = ['git', 'remote', 'update']
    if remote:
        args.append(remote)
    process = subprocess.Popen(args, close_fds=True, universal_newlines=True, cwd=gitdir, env=env)
    process.wait()
    _check(process)

def shortlog(from_commit, to_commit, tree=None):
    process = subprocess.Popen(['git', 'shortlog', from_commit + '..' + to_commit],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    return stdout

def log(options=[], tree=None):
    process = subprocess.Popen(['git', 'log'] + options,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True,
                               cwd=tree)
    stdout, stderr = process.communicate()
    process.wait()
    _check(process, stderr)
    return stdout

def commit_env_vars(commitid, tree=None):
    process = subprocess.Popen(['git', 'show', '--name-only',
                                '--format=format:GIT_AUTHOR_NAME=%an%nGIT_AUTHOR_EMAIL=%ae%nGIT_AUTHOR_DATE=%aD%x00',
                                commitid],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    data = stdout.split('\x00')[0]
    vals = data.split('\n')
    d = {}
    for k, v in map(lambda x: x.split('=', 1), vals):
        d[k] = v
    return d

def commit_message(commitid, tree=None, raw=False):
    if raw:
        fmt = '%B%x00'
    else:
        fmt = '%s%n%n%b%x00'
    process = subprocess.Popen(['git', 'show', '--name-only',
                                '--format=format:%s' % fmt, commitid],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    return stdout.split('\x00')[0]

def remove_config(cfg, tree=None):
    process = subprocess.Popen(['git', 'config', '--unset-all', cfg],
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def ls_remote(branch, tree=None, remote='origin'):
    process = subprocess.Popen(['git', 'ls-remote', remote, 'refs/heads/' + branch],
                               stdout=subprocess.PIPE,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    sha = stdout.split()[0]
    if not _sha_re.match(sha):
        raise SHAError()
    return sha

def list_branches(pattern, tree=None, remote='origin'):
    process = subprocess.Popen(['git', 'ls-remote', '--heads', '--quiet', '--refs',
                                remote, 'refs/heads/' + pattern],
                               stdout=subprocess.PIPE,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    output = stdout.strip()
    if not output:
        return []
    items = output.split('\n')
    items = [i.split() for i in items]
    for i, branch in items:
        if not _sha_re.match(i):
            raise SHAError()
        assert branch.startswith('refs/heads/')
    return [i[1][11:] for i in items]

def checkout(commit, options=[], tree=None):
    process = subprocess.Popen(['git', 'checkout'] + options + [commit],
                               cwd=tree)
    process.wait()
    _check(process)

def commit(msg, tree=None, env={}, opts=[]):
    stdin = tempfile.NamedTemporaryFile(mode='wr')
    stdin.write(msg)
    stdin.seek(0)
    process = subprocess.Popen(['git', 'commit', '--file=-'] + opts,
                               stdin=stdin.file, universal_newlines=True, env=env,
                               cwd=tree)
    process.wait()
    _check(process)

def push(opts=[], tree=None):
    process = subprocess.Popen(['git', 'push'] + opts,
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def log_commits(from_commit, to_commit, tree=None, options=None):
    if from_commit is None:
        commitlist = to_commit
    else:
        commitlist = from_commit + '..' + to_commit
    process = subprocess.Popen(['git', 'log', '--first-parent', '--format=format:%H'] +
                               (options or []) + [commitlist],
                               stdout=subprocess.PIPE,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    vals = stdout.split()
    vals.reverse()
    return vals

def commit_env_vars(commitid, tree=None):
    process = subprocess.Popen(['git', 'show', '--name-only',
                                '--format=format:GIT_AUTHOR_NAME=%an%nGIT_AUTHOR_EMAIL=%ae%nGIT_AUTHOR_DATE=%aD%x00',
                                commitid],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    data = stdout.split('\x00')[0]
    vals = data.split('\n')
    d = {}
    for k, v in map(lambda x: x.split('=', 1), vals):
        d[k] = v
    return d

def commit_date(commitid, tree=None):
    import datetime
    process = subprocess.Popen(['git', 'show', '--name-only',
                                '--format=format:%ct%x00',
                                commitid],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True,
                               cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    ts = int(stdout.split('\x00')[0])
    return datetime.datetime.utcfromtimestamp(ts)

def rm(opts=[], tree=None):
    process = subprocess.Popen(['git', 'rm'] + opts,
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def reset(opts=[], tree=None):
    process = subprocess.Popen(['git', 'reset'] + opts,
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def clean(opts=[], tree=None):
    process = subprocess.Popen(['git', 'clean'] + opts,
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def is_modified(tree=None, ignore=[]):
    process = subprocess.Popen(['git', 'status', '--porcelain', '-z'],
                               universal_newlines=True, cwd=tree,
                               stdout=subprocess.PIPE)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    modified = stdout.split('\0')
    for m in modified:
        if not m:
            continue
        if m[3:] in ignore:
            continue
        return True
    return False

def merge_base(rev1, rev2, tree=None):
    process = subprocess.Popen(['git', 'merge-base', rev1, rev2],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)

    sha = stdout.strip()
    if not _sha_re.match(sha):
        raise SHAError()
    return sha

def tag(name, commit='HEAD', tree=None):
    process = subprocess.Popen(['git', 'tag', name, commit],
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def submodule(opts, tree=None):
    process = subprocess.Popen(['git', 'submodule'] + opts,
                               close_fds=True, universal_newlines=True, cwd=tree)
    process.wait()
    _check(process)

def submodule_status(tree=None):
    process = subprocess.Popen(['git', 'submodule', 'status'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)
    result = []
    for line in stdout.split('\n'):
        if not line:
            continue
        tag = line[0]
        tok = line[1:].split()
        sha1 = tok[0]
        loc = tok[1]
        result.append((tag, sha1, loc))
    return result

def write_tree(tree=None):
    process = subprocess.Popen(['git', 'write-tree'],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               universal_newlines=True, cwd=tree)
    stdout = process.communicate()[0]
    process.wait()
    _check(process)

    sha = stdout.strip()
    if not _sha_re.match(sha):
        raise SHAError()
    return sha

def commit_tree(tree_id, parents, message, tree=None, env=None):
    _parents = []
    for parent in parents:
        _parents.extend(['-p', parent])
    process = subprocess.Popen(['git', 'commit-tree', tree_id] + _parents,
                               universal_newlines=True, cwd=tree, env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    stdout = process.communicate(message)[0]
    process.wait()
    _check(process)

    sha = stdout.strip()
    if not _sha_re.match(sha):
        raise SHAError()
    return sha

def get_note(notes_ref, commit, tree=None):
    process = subprocess.Popen(['git', 'notes', '--ref', notes_ref, 'show', commit],
                               cwd=tree, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout = process.communicate()[0]
    process.wait()
    if process.returncode != 0:
        return None
    return stdout

def set_note(notes_ref, commit, note, tree=None, env=None):
    process = subprocess.Popen(['git', 'notes', '--ref', notes_ref, 'add', '-f', '-F', '-', commit],
                               cwd=tree, env=env, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    process.communicate(note)
    process.wait()
    _check(process)

def fetch(ref, repo='origin', tree=None):
    process = subprocess.Popen(['git', 'fetch', repo, ref], cwd=tree)
    process.wait()
    _check(process)

#!/usr/bin/env python
'''
Removes unnecessary code to create a "pruned" version
for projects. Additionally, it can rename all symbols
in mac80211 to allow for multiple wireless drivers to
be installed on a system.
'''

import sys, os, subprocess, shutil, re, itertools
from lib import kconfig
from lib import linuxmake as make

source_dir = os.path.abspath(os.path.dirname(__file__))

def parse_defconfig(deffile):
    '''
    Parse a defconfig file and return a list of enabled
    and disabled symbols. Also rewrites the defconfig
    file to remove disabled symbols.
    '''
    enabled = []
    disabled = []
    lines = []
    for l in open(deffile, 'r'):
        l = l.strip()
        if not l:
            lines.append(l)
            continue
        if l[-11:].lower() == ' is not set':
            disabled.append(l[9:-11])
        if l[-2:].lower() == '=n':
            disabled.append(l[7:-2])
        # allow =1/2/3/4 for the few integer symbols we have
        # should probably extend this to use a regex to parse
        if l[-2:].lower() in ('=y', '=m', '=1', '=2', '=3', '=4'):
            enabled.append(l[7:-2])
            lines.append(l)

    # rewrite the file excluding disabled symbols
    f = open(deffile, 'w')
    for l in lines:
        f.write(l)
        f.write('\n')
    return enabled, disabled

def strip_defconfig(deffile, dis):
    '''
    remove disabled symbols from the given defconfig file
    '''
    lines = []
    for l in open(deffile, 'r'):
        l = l.strip()
        if not l:
            lines.append(l)
            continue
        if l[-11:].lower() == ' is not set':
            if l[9:-11] in dis:
                continue
        if l[-2:-1].lower() == '=':
            if l[7:-2] in dis:
                continue
        lines.append(l)
    f = open(deffile, 'w')
    for l in lines:
        f.write(l)
        f.write('\n')
    f.close()

def run_extras(basedir, dis):
    '''
    run config-dependent "extra scripts" that are found int
    intc-scripts/prune/<symbol name>
    '''
    for s in dis:
        script = os.path.join(source_dir, 'prune', s)
        if os.path.exists(script):
            p = subprocess.Popen([script], cwd=basedir)
            p.wait()
            if p.returncode != 0:
                raise Exception('extra script %s failed' % s)

def unifdef(f, dis):
    '''
    run unifdef to remove unneeded code
    '''
    lines = []
    syms = []

    # unifdef can't deal with IS_ENABLED() since it won't know
    # its definition - replace it with an appropriate definition
    for l in open(f, 'r'):
        t = l.strip()
        if t.startswith('#if IS_ENABLED(') and t[-1] == ')':
            s = t[15:-1]
            l = '#if defined(%s) || defined(%s_MODULE)\n' % (s, s)
            if not s in syms:
                syms.append(s)
        lines.append(l)

    # run unifdef on the resulting code lines
    p = subprocess.Popen(['unifdef', '-B'] +
                         ['-UCPTCFG_%s' % s for s in dis] +
                         ['-UCPTCFG_%s_MODULE' % s for s in dis],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out = p.communicate(input=''.join(lines))[0]

    # if there's a trailing empty line remove it
    lines = out.split('\n')
    if lines[-1] == '':
        lines = lines[:-1]

    # write to the output file
    outf = open(f, 'w')
    for l in lines:
        for s in syms:
            # and while at it undo the IS_ENABLED() replacement
            if l == '#if defined(%s) || defined(%s_MODULE)' % (s, s):
                l = '#if IS_ENABLED(%s)' % s
        outf.write(l)
        outf.write('\n')
    outf.close()

    # clean up the child process (it must have exited in communicate())
    p.wait()
    if p.returncode != 0 and p.returncode != 1:
        raise Exception('unifdef failed: %d' % p.returncode)

def get_includes(f, includes):
    '''
    add the includes used in the given file to the passed list
    '''
    for line in open(f, 'r'):
        if line.startswith('#include '):
            includes.append(line.strip()[10:-1].split('/')[-1])

def _prune_src(srcdir, dis):
    '''
    prune the entire source tree from the root "srcdir",
    removing both Makefile things as as well as running
    unifdef
    return the include files used *after* unifdef
    '''
    for root, dirs, files in os.walk(srcdir):
        for f in files:
            if f != 'Makefile':
                continue
            make.prune(root, dis)
    includes = []
    for root, dirs, files in os.walk(srcdir):
        for f in files:
            if not f[-2:] in ('.h', '.c'):
                continue
            unifdef(os.path.join(root, f), dis)
            get_includes(os.path.join(root, f), includes)
    return includes


def prune(defconfig, verify, basedir):
    '''
    do the entire prune for the given defconfig, with or without verification
    '''
    allowed_unset_syms = [x.strip() for x in open('intc-scripts/publishable-options')]
    # also use publishable-options-<defconfig> but don't fail if it doesn't exist
    try:
        allowed_unset_syms.extend([x.strip() for x in open('intc-scripts/publishable-options-%s' % defconfig)])
    except IOError:
        pass
    en, dis = parse_defconfig(os.path.join(basedir, 'defconfigs', defconfig))

    # get the symbols that can be found starting from iwlwifi's Kconfig
    # (follows the files source'd into this one, which is Kconfig.noupstream)
    ct = kconfig.ConfigTree('drivers/net/wireless/intel/iwlwifi/Kconfig',
                            basedir=basedir)
    syms = ct.symbols()
    # verify the symbols are enabled or disabled or allowed to be unset
    for sym in syms:
        if not sym in en and not sym in dis and not sym in allowed_unset_syms:
            if verify:
                assert False, '%s state not known!' % sym
            else:
                print('%s state not known, assuming allowed!' % sym)

    drv_dis = [s for s in dis if s in syms]
    ct.remove_symbols(drv_dis)

    # do the same thing over again for mac80211
    ct = kconfig.ConfigTree('net/mac80211/Kconfig',
                            basedir=basedir)
    syms = ct.symbols()
    for sym in syms:
        if not sym in en and not sym in dis and not sym in allowed_unset_syms:
            if verify:
                assert False, '%s state not known!' % sym
            else:
                print('%s state not known, assuming allowed!' % sym)
    mac_dis = [s for s in dis if s in syms]
    ct.remove_symbols(mac_dis)

    dis = drv_dis + mac_dis

    run_extras(basedir, dis)

    includes = _prune_src(os.path.join(basedir, 'drivers', 'net', 'wireless', 'intel', 'iwlwifi'), dis)
    inc = _prune_src(os.path.join(basedir, 'net', 'mac80211'), dis)
    includes.extend(inc)
    inc = _prune_src(os.path.join(basedir, 'include', 'net'), dis)
    includes.extend(inc)
    local = ''
    for l in open(os.path.join(basedir, 'local-symbols'), 'r'):
        if not l[:-2] in dis:
            local += l
    lf = open(os.path.join(basedir, 'local-symbols'), 'w')
    lf.write(local)
    lf.close()

    if verify:
        verify_files_ok = [l.strip() for l in open(os.path.join(basedir, 'intc-scripts', 'publishable-files'))]
        try:
            verify_files_ok.extend([
              l.strip() for l in open(os.path.join(basedir, 'intc-scripts', 'publishable-files-%s' % defconfig))
            ])
        except:
            pass

    # strip or remove defconfigs
    try:
        publishable_defconfigs = [l.strip() for l in open(os.path.join(basedir, 'intc-scripts', 'publishable-defconfigs-%s' % defconfig))]
    except:
        publishable_defconfigs = []
    defconfigs = os.path.join(basedir, 'defconfigs')
    for f in os.listdir(defconfigs):
        if f in publishable_defconfigs:
            strip_defconfig(os.path.join(defconfigs, f), dis)
            continue
        if f == defconfig:
            continue
        os.unlink(os.path.join(defconfigs, f))

    # point the default defconfig to the prune one
    os.unlink(os.path.join(basedir, 'defconfig'))
    os.symlink('defconfigs/' + defconfig, 'defconfig')

    # clean up scripts (other than the ones we should publish)
    publishable_scripts = [l.strip() for l in open(os.path.join(basedir, 'intc-scripts', 'publishable-files'))]
    publishable_scripts = [x[13:] for x in publishable_scripts if x.startswith('intc-scripts/')]
    intc_scripts_dir = os.path.join(basedir, 'intc-scripts')
    for f in os.listdir(intc_scripts_dir):
        if f in publishable_scripts:
            continue
        rmf = os.path.join(intc_scripts_dir, f)
        if os.path.isdir(rmf):
            shutil.rmtree(rmf)
        else:
            os.unlink(rmf)

    os.unlink(os.path.join(basedir, 'TODO-Quasar'))

    shutil.rmtree(os.path.join(basedir, 'Documentation'))

    for root, dirs, files in os.walk(os.path.join(basedir, 'drivers/net/wireless/intel/iwlwifi')):
        for file in files:
            if file[-2:] == '.h':
                if not file in includes:
                    os.unlink(os.path.join(root, file))

    for root, dirs, files in os.walk(os.path.join(basedir, 'drivers/net/wireless/intel/iwlwifi'),
                                     topdown=False):
        if not files:
            os.rmdir(root)

    if verify:
        for root, dirs, files in os.walk(basedir):
            for d in list(dirs):
                full = os.path.join(root, d, '*')
                if full[:2] == './':
                    full = full[2:]
                if full in verify_files_ok:
                    dirs.remove(d)
            for e in itertools.chain(dirs, files):
                full = os.path.join(root, e)
                if full[:2] == './':
                    full = full[2:]
                assert full in verify_files_ok, "Wrong file: %s" % full

def get_files(dirs):
    for d in dirs:
        for root, dirs, files in os.walk(d):
            for f in files:
                yield os.path.join(root, f)

def create_modcompat(basedir):
    '''
    change module and symbol names to have "iwl-"/"__iwl_" prefix;
    this allows having both (for example) mac80211.ko and iwl-mac80211.ko
    on a single system, and due to the renamed symbols the correct one
    will be loaded when a driver needing one or the other is loaded
    '''
    # change module names
    filename = os.path.join(basedir, 'net/mac80211/Makefile')
    data = open(filename, 'r').read()
    data = data.replace('mac80211-', 'iwl-mac80211-')
    data = data.replace('mac80211.o', 'iwl-mac80211.o')
    open(filename, 'w').write(data)

    filename = os.path.join(basedir, 'net/wireless/Makefile')
    data = open(filename, 'r').read()
    data = data.replace('cfg80211-', 'iwl-cfg80211-')
    data = data.replace('cfg80211.o', 'iwl-cfg80211.o')
    open(filename, 'w').write(data)

    # change symbol names
    redef_hdr = open(os.path.join(basedir, 'backport-include/backport/redef-syms.h'), 'w')
    redef_hdr.write('#ifndef __IWL_SYM_REDEFS_H\n#define __IWL_SYM_REDEFS_H\n')
    unredef_hdr = open(os.path.join(basedir, 'backport-include/backport/undef-syms.h'), 'w')
    unredef_hdr.write('#undef __IWL_SYM_REDEFS_H\n')
    syms = []
    for f in get_files([os.path.join(basedir, 'net/wireless'),
                        os.path.join(basedir, 'net/mac80211')]):
        if "wext-" in f:
            continue
        for line in open(f, 'r'):
            if line.startswith('EXPORT_SYMBOL'):
                sym = line.replace('(', ')').split(')')[1]
                syms.append(sym)
    syms.sort()
    for sym in syms:
        redef_hdr.write('#define %s __iwl_%s\n' % (sym, sym))
        unredef_hdr.write('#undef %s\n' % sym)

    redef_hdr.write('#endif /* __IWL_SYM_REDEFS_H */\n')
    redef_hdr.close()
    unredef_hdr.close()

    bphdr = open(os.path.join(basedir, 'backport-include/backport/backport.h'), 'a')
    bphdr.write('\n\n#include <backport/redef-syms.h>\n')
    bphdr.close()

    # some tracing stuff needs to be specially handled ...
    trace_fn = os.path.join(basedir, 'net/wireless/trace.h')
    trace_f = open(trace_fn, 'r')
    trace_d = trace_f.read()
    trace_f.close()
    trace_f = open(trace_fn, 'w')
    trace_f.write('#include <backport/undef-syms.h>\n\n')
    trace_f.write(trace_d)
    trace_f.write('\n#include <backport/redef-syms.h>\n')
    trace_f.close()

def create_maccompat(basedir):
    '''
    change mac80211 module/symbol names to have "iwl-"/"__iwl_" prefix,
    adjust Kconfig and Makefiles to allow dropping in another version
    of mac80211 and loading both
    '''
    # move directory
    shutil.move(os.path.join(basedir, 'net/mac80211'),
                os.path.join(basedir, 'net/iwl-mac80211'))

    filename = os.path.join(basedir, 'Kconfig.sources')
    data = open(filename, 'r').read()
    data = data.replace('source "$BACKPORT_DIR/net/mac80211/Kconfig"',
                        'source "$BACKPORT_DIR/net/iwl-mac80211/Kconfig"')
    open(filename, 'w').write(data)

    filename = os.path.join(basedir, 'Makefile.kernel')
    data = open(filename, 'r').read()
    data = data.replace('+= net/mac80211/', '+= net/iwl-mac80211/')
    open(filename, 'w').write(data)

    # move include file - and replace everywhere
    os.rename(os.path.join(basedir, 'include/net/mac80211.h'),
              os.path.join(basedir, 'include/net/iwl-mac80211.h'))

    for root, dirs, files in os.walk(basedir):
        if '.git' in dirs:
            dirs.remove('.git')
        for name in files:
            fn = os.path.join(root, name)
            data = open(fn, 'r').read()

            if name.startswith('Kconfig'):
                data = data.replace(' MAC80211', ' IWL_MAC80211')
            else:
                data = data.replace('<net/mac80211.h>', '<net/iwl-mac80211.h>')
                data = data.replace('CPTCFG_MAC80211', 'CPTCFG_IWL_MAC80211')
                data = data.replace('TRACE_SYSTEM mac80211',
                                    'TRACE_SYSTEM iwl_mac80211')

            f = open(fn, 'w')
            f.write(data)
            f.close()

    # change module names
    filename = os.path.join(basedir, 'net/iwl-mac80211/Makefile')
    data = open(filename, 'r').read()
    data = data.replace('mac80211-', 'iwl-mac80211-')
    data = data.replace('mac80211.o', 'iwl-mac80211.o')
    f = open(filename, 'w')
    f.write(data)
    f.close()

    # change symbol names
    redef_hdr = open(os.path.join(basedir, 'include/net/iwl-mac80211-syms.h'), 'w')
    redef_hdr.write('#ifndef __IWL_SYM_REDEFS_H\n#define __IWL_SYM_REDEFS_H\n')
    syms = []
    for f in get_files([os.path.join(basedir, 'net/iwl-mac80211')]):
        for line in open(f, 'r'):
            if line.startswith('EXPORT_SYMBOL'):
                sym = line.replace('(', ')').split(')')[1]
                syms.append(sym)
    syms.sort()
    for sym in syms:
        redef_hdr.write('#define %s __iwl_%s\n' % (sym, sym))

    redef_hdr.write('#endif /* __IWL_SYM_REDEFS_H */\n')
    redef_hdr.close()

    fn = os.path.join(basedir, 'include/net/iwl-mac80211.h')
    data = open(fn, 'r').read()
    f = open(fn, 'w')
    f.write('#include <net/iwl-mac80211-syms.h>\n')
    f.write(data)
    f.close()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='remove unnecessary code')
    parser.add_argument('defconfig', metavar='defconfig-file', type=str,
                        help='the defconfig file to use')
    parser.add_argument('basedir', metavar='basedir', type=str, nargs='?', default='.',
                        help='the base directory to work from (default=.)')
    parser.add_argument('--noverify', dest='noverify', action='store_const',
                        const=True, default=False,
                        help='don\'t verify the code/Kconfig')
    parser.add_argument('--modcompat', dest='modcompat', action='store_const',
                        const=True, default=False,
                        help='create module compatibility')
    parser.add_argument('--maccompat', dest='maccompat', action='store_const',
                        const=True, default=False,
                        help='create mac80211 compatibility')
    args = parser.parse_args()
    prune(args.defconfig, not args.noverify, args.basedir)
    if args.modcompat:
        create_modcompat(args.basedir)
    if args.maccompat:
        create_maccompat(args.basedir)

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

#
# Small helper library to read and manipulate kernel Makefiles
#

import os, shutil

def prune(d, dis):
    mf = open(os.path.join(d, 'Makefile'), 'r')
    out = ''
    rm_files = set()
    used_files = set()
    for l in mf:
        ignore = False

        if '-$(CPTCFG_' in l:
            _files = l.split('=')[1]
            _files = _files.split()
            files = set()
            for f in _files:
                if f[-2:] == '.o':
                    files.add(f[:-1] + 'c')
                else:
                    files.add(f)
        else:
            files = set()

        for sym in dis:
            if ('-$(CPTCFG_%s)' % sym) in l:
                ignore = True

        if not ignore:
            out += l
            used_files |= files
        else:
            rm_files |= files
    rm_files -= used_files
    mf.close()
    mf = open(os.path.join(d, 'Makefile'), 'w')
    mf.write(out)
    mf.close()

    for r in rm_files:
        f = os.path.join(d, r)
        if os.path.isdir(f):
            shutil.rmtree(f)
        else:
            try:
                os.unlink(f)
            except:
                # probably already gone
                pass

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
# Small helper library to manipulate Kconfig files
#

import os, re

src_line = re.compile(r'^source\s+"?(?P<src>[^\s"]*)"?\s*$')
cfg_line = re.compile(r'^(config|menuconfig)\s+(?P<sym>[^\s]*)')
other_line = re.compile(r'^(menu|endmenu|comment)\s+')

class ConfigTree(object):
    def __init__(self, rootfile, basedir=None):
        if basedir is None:
            self.basedir = os.path.dirname(rootfile)
            self.rootfile = os.path.basename(rootfile)
        else:
            self.basedir = basedir
            self.rootfile = rootfile

    def _walk(self, f):
        yield f
        for l in open(os.path.join(self.basedir, f), 'r'):
            m = src_line.match(l)
            if m and os.path.exists(os.path.join(self.basedir, m.group('src'))):
                for i in self._walk(m.group('src')):
                    yield i

    def symbols(self):
        syms = []
        for nf in self._walk(self.rootfile):
            for l in open(os.path.join(self.basedir, nf), 'r'):
                m = cfg_line.match(l)
                if m:
                    syms.append(m.group('sym'))
        return syms

    def remove_symbols(self, syms):
        for nf in self._walk(self.rootfile):
            out = ''
            skip = False
            for l in open(os.path.join(self.basedir, nf), 'r'):
                m = cfg_line.match(l)
                if m:
                    skip = False
                    if m.group('sym') in syms:
                        skip = True
                if src_line.match(l) or other_line.match(l):
                    skip = False
                if not skip:
                    out += l
            outf = open(os.path.join(self.basedir, nf), 'w')
            outf.write(out)
            outf.close()

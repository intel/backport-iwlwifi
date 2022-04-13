#
# INTEL CONFIDENTIAL
#
# Copyright (C) 2018 - 2020 Intel Corporation
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
import subprocess
import re
import time

COPYRIGHT_CURRENT_OWNER_S = "Intel Corporation"
COPYRIGHT_CURRENT_OWNER = COPYRIGHT_CURRENT_OWNER_S.encode('ascii')

class Copyright(object):
    def __init__(self):
        self.type = None
        self.years = set()
        self.owner = None

def check_copyright(file_types, missing_fn=None):
    file_types = [ft.encode('ascii') for ft in file_types]
    err = 0
    curyear = time.gmtime().tm_year

    p = subprocess.Popen(["git", "show", "-U100000", "-M", "HEAD"],
                         stdout=subprocess.PIPE)
    c = p.communicate()[0]
    p.wait()

    changetype = br'(?P<type>[-+ ])'
    pfx = b'.*'
    copyright = br'Copyright[()Cc ]*'
    year_or_range = br'((2[0-9]{3})\s*-\s*)?(2[0-9]{3})\s*,?\s*'
    years = br'(?P<years>(' + year_or_range + b')+)'
    owner = br'(?P<owner>.*?)'
    reserved = br'(\. All rights reserved\.)?'
    copyright_re = re.compile(br'^' + changetype + pfx + copyright + years + owner + reserved + b'$')

    diffs = c.split(b'\n+++ ')
    for d in diffs:
        # don't check deleted files or other garbage
        lines = d.split(b'\n')
        if not lines[0].startswith(b'b/'):
            continue
        filename = lines[0][2:]
        if not filename.split(b'.')[-1] in file_types:
            continue
        lines = [x for x in lines if len(x) and x[0] in b' +-']
        done = False
        lines_iter = iter(lines)
        next_section = ""
        while not done:
            copyrights = set()
            done = True
            section = next_section
            for line in lines_iter:
                # stupid trick to avoid it falling over itself
                if (b'BSD ' + b'LICENSE') in line:
                    done = False
                    next_section = " (BSD section)"
                    break
                m = copyright_re.match(line)
                if not m:
                    continue
                c = Copyright()
                c.type = m.group('type')
                years = m.group('years')
                for g in years.split(b','):
                    g = g.strip()
                    if not g:
                        # nothing to do, found a trailing "," in the year list
                        pass
                    elif b'-' in g:
                        beginyear, endyear = [int(x.strip()) for x in g.split(b'-')]
                        c.years |= set(range(beginyear, endyear + 1))
                    else:
                        c.years |= set([int(g)])
                c.owner = m.group('owner')
                copyrights.add(c)
            # preload what we want to reduce checks below
            old_owners = {
                COPYRIGHT_CURRENT_OWNER: set(),
            }
            new_owners = {
                COPYRIGHT_CURRENT_OWNER: set(),
            }
            for c in copyrights:
                if not c.owner in old_owners:
                    old_owners[c.owner] = set()
                if not c.owner in new_owners:
                    new_owners[c.owner] = set()

                if c.type in b' +':
                    new_owners[c.owner] |= c.years
                if c.type in b' -':
                    old_owners[c.owner] |= c.years

            for owner in new_owners:
                if owner == COPYRIGHT_CURRENT_OWNER:
                    ign = set([curyear])
                else:
                    ign = set()
                if new_owners[owner] | ign != old_owners[owner] | ign:
                    err = 2
                    print("%s: please do not modify old copyright lines/add past years%s" % (filename.decode(), section))
                    new_owners[owner] = old_owners[owner]
                    break
            if not curyear in new_owners[COPYRIGHT_CURRENT_OWNER]:
                err = 2
                if (curyear - 1) in new_owners[COPYRIGHT_CURRENT_OWNER]:
                    print('%s: please extend %s Copyright for %d%s' % (filename.decode(), COPYRIGHT_CURRENT_OWNER_S, curyear, section))
                else:
                    print('%s: please add "Copyright (C) %d %s"%s' % (filename.decode(), curyear, COPYRIGHT_CURRENT_OWNER_S, section))
                if missing_fn:
                    missing_fn(filename)

    if err:
        print('see https://soco.intel.com/docs/DOC-1015054 for more information')

    return err

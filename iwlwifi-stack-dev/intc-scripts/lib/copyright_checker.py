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
import subprocess
import re
import time

COPYRIGHT_CURRENT_OWNER = "Intel Corporation"

class Copyright(object):
    type = None
    beginyear = None
    endyear = None
    owner = None

def check_copyright(file_types):
    err = 0
    curyear = time.gmtime().tm_year

    p = subprocess.Popen(["git", "show", "-U100000", "-M", "HEAD"],
                         stdout=subprocess.PIPE)
    c = p.communicate()[0]
    p.wait()

    copyright_re = re.compile(r'^(?P<type>[-+ ]).*Copyright[()Cc ]*((?P<beginyear>2[0-9]{3})\s*-\s*)?(?P<endyear>2[0-9]{3})\s*(?P<owner>.*)')

    diffs = c.split('\n+++ ')
    for d in diffs:
        # don't check deleted files or other garbage
        lines = d.split('\n')
        if not lines[0].startswith('b/'):
            continue
        filename = lines[0][2:]
        if not filename.split('.')[-1] in file_types:
            continue
        lines = filter(lambda x: len(x) and x[0] in ' +-', lines)
        done = False
        lines_iter = iter(lines)
        next_section = ""
        while not done:
            copyrights = set()
            done = True
            section = next_section
            for line in lines_iter:
                # stupid trick to avoid it falling over itself
                if ('BSD ' + 'LICENSE') in line:
                    done = False
                    next_section = " (BSD section)"
                    break
                m = copyright_re.match(line)
                if not m:
                    continue
                c = Copyright()
                c.type = m.group('type')
                endyear = m.group('endyear')
                beginyear = m.group('beginyear') or endyear
                c.beginyear = int(beginyear)
                c.endyear = int(endyear)
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

                if c.type in ' +':
                    new_owners[c.owner] |= set(range(c.beginyear, c.endyear + 1))
                if c.type in ' -':
                    old_owners[c.owner] |= set(range(c.beginyear, c.endyear + 1))

            for owner in new_owners:
                if owner == COPYRIGHT_CURRENT_OWNER:
                    ign = set([curyear])
                else:
                    ign = set()
                if new_owners[owner] | ign != old_owners[owner] | ign:
                    err = 2
                    print("%s: please do not modify old copyright lines/add past years%s" % (filename, section))
                    new_owners[owner] = old_owners[owner]
                    break
            if not curyear in new_owners[COPYRIGHT_CURRENT_OWNER]:
                err = 2
                if (curyear - 1) in new_owners[COPYRIGHT_CURRENT_OWNER]:
                    print('%s: please extend %s Copyright for %d%s' % (filename, COPYRIGHT_CURRENT_OWNER, curyear, section))
                else:
                    print('%s: please add "Copyright (C) %d %s"%s' % (filename, curyear, COPYRIGHT_CURRENT_OWNER, section))

    if err:
        print('see https://soco.intel.com/docs/DOC-1015054 for more information')

    return err

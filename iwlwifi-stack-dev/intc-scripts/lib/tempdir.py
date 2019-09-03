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

"""
simple tempdir wrapper object for 'with' statement

Usage:
with tempdir.Tempdir() as tmpdir:
    os.chdir(tmpdir)
    # do something
"""

import tempfile
import shutil

class Tempdir(object):
    """
    Context class for a temporary directory that is removed when the context
    is closed.
    """
    def __init__(self, suffix='', prefix='', tmpdir=None, nodelete=False):
        self.suffix = suffix
        self.prefix = prefix
        self.dir = tmpdir
        self.nodelete = nodelete
        self._name = None

    def __enter__(self):
        self._name = tempfile.mkdtemp(suffix=self.suffix,
                                      prefix=self.prefix,
                                      dir=self.dir)
        return self._name

    def __exit__(self, _type, value, traceback):
        if self.nodelete:
            print('not deleting directory %s!' % self._name)
        else:
            shutil.rmtree(self._name)

# backward compatibility
tempdir = Tempdir

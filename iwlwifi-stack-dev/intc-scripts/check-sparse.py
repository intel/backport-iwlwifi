#!/usr/bin/env python

import sys, re

class Analyser(object):
    def __init__(self, f):
        self._f = f
        self._buf = None

    def _read_line(self):
        if not self._buf is None:
            ret = self._buf
            self._buf = None
            return ret
        line = self._f.readline()
        return line

    def _push_line(self, line):
        assert self._buf is None
        self._buf = line

    def _read_message(self):
        msg = None
        while True:
            m = None
            while not m:
                line = self._read_line()
                if not line:
                    return msg
                m = re.match(r".*?([^/]*):([0-9]*):([0-9]*): (.*)$", line)
                if msg and not m:
                    break
            if msg and not m:
                break
            (filename, lineno, offs, msgline) = m.groups()
            if msg is None:
                msg = [filename, lineno, offs, [msgline], line]
            else:
                if msg[:3] == [filename, lineno, offs]:
                    msg[3].append(msgline)
                    msg[4] += line
                else:
                    self._push_line(line)
                    break
        return msg

    def _ignore(self, msg):
        filename, lineno, offs, msg = msg[:4]

        # this comes from wait_event*() and there's nothing we can do about it
        if msg[0] == "warning: symbol '__ret' shadows an earlier one":
            return True

        # this happens - nothing to be too worried about
        if (filename == 'tx.c' and
            msg[0] == "warning: potentially expensive pointer subtraction"):
            return True

        # mac80211 does this, and it's not really all that bad
        if msg[0] == "warning: Variable length array is used.":
            return True

        # this may happen due to an upstream change from int -> unsigned int,
        # so on older kernels we can get this warning
        if (filename == "mac80211_hwsim.c" and
            msg[0] == "warning: incorrect type in initializer (different signedness)"):
            return True

        return False

    def check(self):
        errors = False
        while True:
            msg = self._read_message()
            if not msg:
                break
            if not self._ignore(msg):
                errors = True
                # prefix everything with space to preserve formatting in gerrit
                print '', msg[4],

        return not errors

if __name__ == "__main__":
    if Analyser(sys.stdin).check():
        sys.exit(0)
    sys.exit(1)

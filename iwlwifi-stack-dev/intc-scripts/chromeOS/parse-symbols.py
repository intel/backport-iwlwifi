#!/usr/bin/env python
"""
This script reads stdin and
 * finds all EXPORT_SYMBOL[_GPL] statements
 * including their surrounding #ifdefs (and similar)
 * cleans up the surrounding #ifdefs to not have everything
"""

import sys, re

def debug(data):
    lno = 0
    for l in data:
        sys.stdout.write('%.3d: %s' % (lno, ''.join(l)))
        lno += 1

def optimise(data):
    '''
    "optimise" the given data, in the sense that empty #if/#endif
    blocks are removed, as well as the #else or #elif statement of
    empty #else/#elif/#end blocks.
    This is done until the output no longer changes, which thus
    will also remove empty #if/#else/#endif blocks (or even with
    multiple #elif statements), in multiple iterations.
    '''
    old_len = -1
    while old_len != len(data):
        old_len = len(data)

        for idx in range(len(data) - 1):
            item = data[idx][0]
            next = data[idx + 1][0]

            # remove useless #if/#endif pair
            if item.startswith('#if') and next.startswith('#end'):
                data = data[:idx] + data[idx + 2:]
                # need to break since we modified the 'data' list
                break

            # remove useless (directly followed by #endif) #else or #elif
            if item.startswith('#el') and next.startswith('#end'):
                data = data[:idx] + data[idx + 1:]
                # need to break since we modified the 'data' list
                break
    return data

def parse(input):
    # first read only the relevant lines into 'output'
    # the data structure we use is a list of lists, each inner list containing
    # all lines that belong to a single statement, which may consist of more
    # than one line due to continuations (backslash at EOL)
    output = []

    # track if we're on a line with continuation right now
    continuation=False

    for line in input:
        if continuation:
            # check if it still continues - rstrip() removes LF/CR/CRLF
            continuation = line.rstrip().endswith('\\')
            # append the continuation line to the current condition list
            output[-1].append(line)
            continue

        if line.startswith('#if') or line.startswith('#el') or line.startswith('#end'):
            output.append([line,])
            continuation = line.rstrip().endswith('\\')
        elif re.match(r'EXPORT_SYMBOL(_GPL)?\(([^)]*)\).*', line):
            out = re.sub(r'EXPORT_SYMBOL(_GPL)?\(([^)]*)\).*',
                         r'#define \2 __iwl7000_\2',
                         line)
            output.append([out,])

    # now optimize the whole thing
    output = optimise(output)

    # and finally write it out
    for l in output:
        sys.stdout.write(''.join(l))

if __name__ == '__main__':
    parse(sys.stdin)

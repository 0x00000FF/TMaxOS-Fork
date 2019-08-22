#!/usr/bin/python
#
# Copyright 2012-2018 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# find_tests(), runtest() and main() inspired by regrtest.py from Python 3.1
# Copyright (c) 2001-2010 Python Software Foundation; All Rights Reserved
#


from __future__ import print_function
import os
import sys


def find_tests(testdir=None, testscripts=[]):
    '''Find tests'''
    if not testdir:
        if __name__ == '__main__':
            fn = sys.argv[0]
        else:
            print("TODO: find_tests() when imported")
            sys.exit(1)

        testdir = os.path.dirname(fn)

    if len(testscripts) > 1:
        names = testscripts[1:]
    else:
        names = os.listdir(testdir)
    tests = []
    for name in names:
        if name[:5] == "test_" and name[-3:] == ".py":
            tests.append(name[:-3])
    tests.sort()
    return tests


def runtest(test):
    '''Run test'''
    pkg = __import__("tests.unit." + test, globals(), locals(), [])
    unit_pkg = getattr(pkg, "unit")
    mod = getattr(unit_pkg, test)
    print(test)
    mod.test_main()


if __name__ == '__main__':
    # Create the unittest symlink so imports work
    if not os.path.islink("./ufw"):
        os.symlink("./src", "./ufw")

    # Replace runner.py's directory from the search path, and add our own
    # so we can properly namespace our modules
    d = os.path.abspath(os.path.normpath(os.path.dirname(sys.argv[0])))
    testdir = os.path.dirname(d)
    testdir = os.path.dirname(os.path.dirname(d))
    i = len(sys.path)
    while i >= 0:
        i -= 1
        if os.path.abspath(os.path.normpath(sys.path[i])) == d:
            sys.path[i] = testdir

    print("DEBUG: sys.path=%s" % sys.path)
    tests = find_tests(testscripts=sys.argv)
    print("DEBUG: test=%s" % str(tests))

    # Import this here, so we are guaranteed to get ours from topdir
    from tests.unit.support import TestFailed

    passed = []
    failed = []
    skipped = []
    for test in tests:
        try:
            runtest(test)
            passed.append(test)
        except KeyboardInterrupt: # kill this test, but still do others
            print("")
            break
        except TestFailed as e:
            failed.append(test)
        except Exception:
            raise

        # cleanup
        for m in list(sys.modules.keys()):
            if m.startswith("tests.unit.") and m != "tests.unit.support":
                try:
                    del sys.modules[m]
                except KeyError:
                    pass

    # Cleanup our symlink
    if os.path.islink("./ufw"):
        os.unlink("./ufw")

    print("")
    print("------------------")
    print("Unit tests summary")
    print("------------------")
    print("Total=%d (Passed=%d, Failed=%d)" % (len(passed) + len(failed),
                                               len(passed),
                                               len(failed)))
    if len(failed) > 0:
        sys.exit(1)

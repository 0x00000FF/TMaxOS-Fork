# -*- coding: utf-8 -*-
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
# run_unittest() inspired by Lib/test/support.py from Python 3.1
# Copyright (c) 2001-2010 Python Software Foundation; All Rights Reserved

import unittest
import os
import subprocess
import sys
_ = None

topdir = "./tests/unit/tmp"


class Error(Exception):
    '''Error'''


class TestFailed(Error):
    '''Test failed'''


def skipped(cls, s):
    '''Test skipped'''
    # TODO: fix newline
    # TODO: somehow flag and count this as skipped
    print("skipped: %s" % s)
    return False


def recursive_rm(dirPath, contents_only=False):
    '''recursively remove directory'''
    names = os.listdir(dirPath)
    for name in names:
        path = os.path.join(dirPath, name)
        if os.path.islink(path) or not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    if contents_only is False:
        os.rmdir(dirPath)


def initvars(install_dir):
    import ufw.common

    global _
    _ = init_gettext()

    global topdir
    d = os.path.join(os.path.dirname(os.path.realpath(topdir)),
                     "fake-binaries")
    ufw.common.iptables_dir = d

    ufw.common.config_dir = os.path.join(
                             os.path.realpath(topdir), "ufw/etc")
    ufw.common.state_dir = os.path.join(
                            os.path.realpath(topdir), "ufw/lib/ufw")
    ufw.common.share_dir = os.path.join(
                            os.path.realpath(topdir), "ufw/usr/share/ufw")
    ufw.common.trans_dir = ufw.common.share_dir
    ufw.common.prefix_dir = os.path.join(os.path.realpath(topdir), "ufw/usr")


def run_setup():
    global topdir
    install_dir = os.path.join(topdir, "ufw")
    if os.path.exists(topdir):
        recursive_rm(topdir)
    os.mkdir(topdir)
    sp = subprocess.Popen(['python',
                           './setup.py',
                           'install',
                           '--home=%s' % install_dir],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           universal_newlines=True)
    out, err = sp.communicate()

    if sp.returncode != 0:
        print("setup.py failed: %s" % err)
        sys.exit(1)

    return install_dir


def run_unittest(*classes):
    '''Run tests from classes'''
    install_dir = run_setup()

    initvars(install_dir) # initialize ufw for testing

    suite = unittest.TestSuite()
    for cls in classes:
        suite.addTest(unittest.makeSuite(cls))

    runner = unittest.TextTestRunner(sys.stdout, verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        if len(result.errors) == 1 and not result.failures:
            err = result.errors[0][1]
        elif len(result.failures) == 1 and not result.errors:
            err = result.failures[0][1]
        else:
            err = "multiple errors occurred"
        raise TestFailed(err)

    if os.path.exists(topdir):
        recursive_rm(topdir)


def init_gettext():
    '''Convenience function to setup _'''

    # This is all stolen from src/ufw
    import gettext
    kwargs = {}
    if sys.version_info[0] < 3:
        # In Python 2, ensure that the _() that gets installed into built-ins
        # always returns unicodes.  This matches the default behavior under
        # Python 3, although that keyword argument is not present in the Python
        # 3 API.
        kwargs['unicode'] = True
    gettext.install("ufw", **kwargs)

    # Internationalization
    gettext.bindtextdomain("ufw", \
                           os.path.join('./locales/mo'))
    gettext.textdomain("ufw")
    try:
        # BAW: I'm not sure why both this and the .install() above is here, but
        # let's roll with it for now.  This is the Python 2 version, which
        # ensures we get unicodes.
        _ = gettext.ugettext
    except AttributeError:
        # Python 3 always returns unicodes.
        _ = gettext.gettext

    return _


def check_for_exception(t, expectedException, func, *args):
    try:
        func(*args)
    except expectedException:
        pass
    except Exception:
        t.fail("Unexpected exception thrown for '%s%s:\n%s" % (str(func), str(args), sys.exc_info()[0]))
    else:
        t.fail('%s not thrown' % str(expectedException))


def get_sample_rule_commands_simple():
    '''Return a list of sample rule commands for simple rules.
       Format:
       [
        [ 'rule', <action>, args... ],
        [ 'rule', <action>, args... ],
       ]
    '''

    cmds = []
    for action in ['allow', 'deny', 'reject', 'limit']:
        for dir in ['', 'in', 'out']:
            for log in ['', 'log', 'log-all']:
                for port in ['', '22', 'tcpmux', 'fsp', 'WWW', 'CIFS', \
                             'WWW Full', 'DNS']:
                    for proto in ['', 'tcp', 'udp']:
                        for comment in ['', 'thumbs 👍']:
                            c = []
                            if dir:
                                c.append(dir)
                                if not port:
                                    c.append('on')
                                    c.append('eth0')

                            if log:
                                c.append(log)

                            if not port and 'on' in c:
                                # eg, rule allow in on eth0
                                cmds.append(['rule', action] + c)
                                continue

                            try:
                                int(port)
                                if proto:
                                    # eg, rule action dir log 22/tcp
                                    c.append('%s/%s' % (port, proto))
                                else:
                                    # eg, rule action dir log 22
                                    c.append(port)
                            except ValueError:
                                if proto or not port:
                                    continue
                                else:
                                    # eg, rule action dir log DNS
                                    # eg, rule action dir log tcpmux
                                    c.append(port)

                            if comment:
                                c += ['comment', comment]

                            cmds.append(['rule', action] + c)

    return cmds


def get_sample_rule_commands_extended(v6=False):
    '''Return a list of sample rule commands for extended rules.
       Format:
       [
        [ 'rule', <action>, args... ],
        [ 'rule', <action>, args... ],
       ]
    '''

    dsts = ['', '1.2.3.4', '10.0.0.0/8', 'any', '1.2.3.4!22', \
            '10.0.0.0/8!tcpmux', 'any!fsp', '1.2.3.4!WWW Full', \
            '10.0.0.0/8!CIFS', 'any!DNS']
    srcs = ['', '5.6.7.8', '172.16.0.0/12', 'any', '5.6.7.8!22', \
            '172.16.0.0/12!tcpmux', 'any!fsp', '5.6.7.8!WWW Full', \
            '172.16.0.0/12!CIFS', 'any!DNS']
    if v6:
        dsts = ['', '2001:db8:85a3:8d3:1319:8a2e:370:7341', \
                '1234:db8::/32', 'any', \
                '2001:db8:85a3:8d3:1319:8a2e:370:7341!22', \
                '1234:db8::/32!tcpmux', 'any!fsp', \
                '2001:db8:85a3:8d3:1319:8a2e:370:7341!WWW Full', \
                '1234:db8::/32!CIFS', 'any!DNS']
        srcs = ['', '2001:db8:85a3:8d3:1319:8a2e:370:7342', \
                '5678:fff::/64', 'any', \
                '2001:db8:85a3:8d3:1319:8a2e:370:7342!22', \
                '5678:fff::/64!tcpmux', 'any!fsp', \
                '2001:db8:85a3:8d3:1319:8a2e:370:7342!WWW Full', \
                '5678:fff::/64!CIFS', 'any!DNS']

    cmds = []
    for rule_type in ['rule', 'route']:
        for action in ['allow', 'deny', 'reject', 'limit']:
            for dir in ['', 'in', 'out', 'in on eth0', 'out on eth1',
                        'in on eth0 out on eth1']:
                for log in ['', 'log', 'log-all']:
                    for to in dsts:
                        for frm in srcs:
                            for proto in ['', 'tcp', 'udp']:
                                for comment in ['', 'thumbs 👍']:
                                    dst = ''
                                    dport = ''
                                    if to:
                                        if '!' in to:
                                            (dst, dport) = to.split('!')
                                        else:
                                            dst = to

                                    src = ''
                                    sport = ''
                                    if frm:
                                        if '!' in frm:
                                            (src, sport) = frm.split('!')
                                        else:
                                            src = frm

                                    # We should only output valid rules, so
                                    # short-circuit some invalid ones

                                    # Don't allow mixing services and
                                    # application rules
                                    srvs = ['tcpmux', 'fsp']
                                    apps = ['WWW Full', 'DNS', 'CIFS']
                                    if (dport in srvs and sport in apps) or \
                                       (sport in srvs and dport in apps):
                                        continue

                                    # Don't allow mixing tcp and udp services
                                    if dport != sport and \
                                       dport in srvs and \
                                       sport in srvs:
                                        continue

                                    # Don't allow mixing apps since they all
                                    # have different protocols
                                    if dport != sport and \
                                       dport in apps and \
                                       sport in apps:
                                        continue

                                    # don't mix services and protocols
                                    if ((dport == 'fsp' or sport == 'fsp') \
                                        and proto == 'tcp') or \
                                       ((dport == 'tcpmux' or
                                         sport == 'tcpmux') \
                                         and proto == 'udp'):
                                        continue

                                    # Now start building up the command
                                    c = []
                                    if dir:
                                        if rule_type == 'rule' and \
                                           'in on' in dir and 'out on' in dir:
                                            # non-route rules don't support
                                            # specifying two interfaces
                                            continue
                                        elif rule_type == 'route':
                                            # route rules don't support bare
                                            # 'in' and 'out'
                                            continue
                                        elif 'on' in dir:
                                            c += dir.split()
                                        else:
                                            c.append(dir)

                                    if log:
                                        c.append(log)

                                    if not to and not frm:
                                        # nothing to do (use simple syntax)
                                        continue

                                    if src:
                                        c.append('from')
                                        c.append(src)
                                    if sport:
                                        if sport in apps:
                                            c.append('app')
                                        else:
                                            c.append('port')
                                        c.append(sport)

                                    if dst:
                                        c.append('to')
                                        c.append(dst)
                                    if dport:
                                        if dport in apps:
                                            c.append('app')
                                        else:
                                            c.append('port')
                                        c.append(dport)

                                    # add 'proto' when it makes sense
                                    if proto:
                                        try:
                                            if dport:
                                                int(dport)
                                            if sport:
                                                int(sport)
                                            c.append('proto')
                                            c.append(proto)
                                        except ValueError:
                                            if dport not in apps and \
                                               sport not in apps and \
                                               ((dport == 'fsp' and \
                                                 proto == 'udp') or \
                                                (sport == 'fsp' and \
                                                 proto == 'udp') or \
                                                (dport == 'tcpmux' and \
                                                 proto == 'tcp') or \
                                                (sport == 'tcpmux' and \
                                                 proto == 'tcp')):
                                                    c.append('proto')
                                                    c.append(proto)

                                    if comment:
                                        c += ['comment', comment]

                                    cmds.append([rule_type, action] + c)

    return cmds


def has_proc_net_output():
    '''Determine if /proc/net/tcp|udp[6] have useful information'''
    found = False
    for p in ['tcp', 'udp', 'tcp', 'tcp6']:
        path = os.path.join("/proc/net", p)
        if not os.path.exists(p):
            continue
        with open(p) as f:
            if len(f.readlines()) > 1:  # account for header
                found = True
                break
    return found

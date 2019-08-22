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

import unittest
import tests.unit.support
import ufw.backend_iptables
import ufw.common
import ufw.frontend
import os
import re
import shutil
import time

try: # python 2
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class BackendIptablesTestCase(unittest.TestCase):
    def setUp(self):
        ufw.common.do_checks = False

        for d in [ufw.common.state_dir, ufw.common.config_dir]:
            if not os.path.isdir(d + ".bak"):
                shutil.copytree(d, d + ".bak")

        # don't duplicate all the code for set_rule() from frontend.py so
        # the frontend's set_rule() to exercise our set_rule()
        self.ui = ufw.frontend.UFWFrontend(dryrun=True)

        # for convenience
        self.backend = self.ui.backend

        self.saved_msg_output = ufw.util.msg_output
        self.msg_output = None

        self.prevpath = os.environ['PATH']
        os.environ['PATH'] = "%s:%s" % (ufw.common.iptables_dir,
                                        os.environ['PATH'])

        # update ufw-init-functions to use our fake iptables* commands
        f = os.path.join(ufw.common.state_dir, "ufw-init-functions")
        contents = ""
        for line in open(f).readlines():
            if re.search("^PATH=", line):
                line = "#" + line
                line += 'PATH="%s:%s"\n' % (ufw.common.iptables_dir,
                                            line.split('"')[1])
            contents += line
        open(f + '.new', 'w').write(contents)
        os.rename(f + '.new', f)

    def tearDown(self):
        self.ui = None
        self.backend = None
        os.environ['PATH'] = self.prevpath

        for d in [ufw.common.state_dir, ufw.common.config_dir]:
            if os.path.isdir(d):
                tests.unit.support.recursive_rm(d)
                shutil.copytree(d + ".bak", d)

        if self.msg_output:
            ufw.util.msg_output = self.saved_msg_output
            self.msg_output.close()
            self.msg_output = None

        sysctl = os.path.join(ufw.common.iptables_dir, "sysctl")
        if os.path.exists(sysctl):
            os.unlink(sysctl)

    def _update_sysctl(self, forward=False):
        sysctl = os.path.join(ufw.common.iptables_dir, "sysctl")
        if forward:
            shutil.copy(os.path.join(ufw.common.iptables_dir,
                                     "sysctl-forward-yes"),
                        sysctl)
        else:
            shutil.copy(os.path.join(ufw.common.iptables_dir,
                                     "sysctl-forward-no"),
                        sysctl)

    def _test__do_checks(self):
        '''Test _do_checks()'''
        print("  setting self.backend.do_checks to 'True'")
        self.backend.do_checks = True
        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend._do_checks)
        print("  setting self.backend.do_checks to 'False'")
        self.backend.do_checks = False
        self.backend._do_checks()

    def test_get_default_application_policy(self):
        '''Test get_default_application_policy()'''
        s = self.backend.get_default_application_policy()
        self.assertTrue(s.endswith("skip"))

    def test_set_default_application_policy(self):
        '''Test set_default_application_policy()'''
        self.backend.dryrun = False
        for policy in ['allow', 'deny', 'reject', 'skip']:
            s = self.backend.set_default_application_policy(policy)
            self.assertTrue(policy in s, "Could not find '%s' in:\n%s" % \
                                         (policy, s))

    def test_get_app_rules_from_template(self):
        '''Test get_app_rules_from_template()'''
        pr = ufw.frontend.parse_command(['rule', 'allow', 'CIFS'])
        rules = self.backend.get_app_rules_from_template(pr.data['rule'])
        self.assertEquals(len(rules), 2)
        for r in rules:
            self.assertEquals(r.dapp, 'CIFS')

        pr = ufw.frontend.parse_command(['rule', 'deny',
                                         'from', 'any', 'app', 'CIFS'])
        rules = self.backend.get_app_rules_from_template(pr.data['rule'])
        self.assertEquals(len(rules), 2)
        for r in rules:
            self.assertEquals(r.sapp, 'CIFS')

        pr = ufw.frontend.parse_command(['rule', 'reject',
                                         'to', 'any', 'app', 'CIFS',
                                         'from', 'any', 'app', 'CIFS'])
        rules = self.backend.get_app_rules_from_template(pr.data['rule'])
        self.assertEquals(len(rules), 2)
        for r in rules:
            self.assertEquals(r.dapp, 'CIFS')
            self.assertEquals(r.sapp, 'CIFS')

        pr = ufw.frontend.parse_command(['rule', 'reject',
                                         'to', 'any', 'app', 'WWW',
                                         'from', 'any', 'app', 'WWW Secure'])
        rules = self.backend.get_app_rules_from_template(pr.data['rule'])
        self.assertEquals(len(rules), 1)
        for r in rules:
            self.assertEquals(r.dapp, 'WWW')
            self.assertEquals(r.sapp, 'WWW Secure')

        pr = ufw.frontend.parse_command(['rule', 'allow',
                                         'from', 'any', 'app', 'IPP',
                                         'to', 'any', 'app', 'WWW'])
        rules = self.backend.get_app_rules_from_template(pr.data['rule'])
        self.assertEquals(len(rules), 1)
        for r in rules:
            self.assertEquals(r.sapp, 'IPP')

        pr = ufw.frontend.parse_command(['rule', 'allow', '12345'])
        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend.get_app_rules_from_template,
                              pr.data['rule'])

    def test_update_app_rule(self):
        '''Test upate_app_rule()'''
        self.saved_msg_output = ufw.util.msg_output
        self.msg_output = StringIO()
        ufw.util.msg_output = self.msg_output

        (s, res) = self.backend.update_app_rule('WWW')
        self.assertFalse(res)
        self.assertEquals(s, "")

        pr = ufw.frontend.parse_command([] + ['rule', 'allow', 'CIFS'])
        self.backend.rules.append(pr.data['rule'])
        (s, res) = self.backend.update_app_rule('WWW')
        self.assertFalse(res)
        self.assertEquals(s, "")
        (s, res) = self.backend.update_app_rule('CIFS')
        self.assertTrue(res)
        self.assertTrue('CIFS' in s)

        pr = ufw.frontend.parse_command([] + ['rule', 'allow',
                                         'to', '5678:fff::/64',
                                         'app', 'WWW Secure'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])
        (s, res) = self.backend.update_app_rule('WWW')
        self.assertFalse(res)
        self.assertEquals(s, "")
        (s, res) = self.backend.update_app_rule('WWW Secure')
        self.assertTrue(res)
        self.assertTrue('WWW Secure' in s)

        pr = ufw.frontend.parse_command([] + ['rule', 'allow',
                                         'from', '1234:fff::/64',
                                         'app', 'WWW Secure',
                                         'to', '2345:fff::/64',
                                         'app', 'WWW Full'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])
        (s, res) = self.backend.update_app_rule('WWW')
        self.assertFalse(res)
        self.assertEquals(s, "")
        (s, res) = self.backend.update_app_rule('WWW Full')
        self.assertTrue(res)
        self.assertTrue('WWW Full' in s)

        pr = ufw.frontend.parse_command([] + ['rule', 'allow', 'NFS'])
        self.backend.rules.append(pr.data['rule'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])
        (s, res) = self.backend.update_app_rule('WWW')
        self.assertFalse(res)
        self.assertEquals(s, "")
        (s, res) = self.backend.update_app_rule('NFS')
        self.assertTrue(res)
        self.assertTrue('NFS' in s)

    def test_find_application_name(self):
        '''Test find_application_name()'''
        res = self.backend.find_application_name('WWW')
        self.assertEquals(res, 'WWW')

        res = self.backend.find_application_name('WwW')
        self.assertEquals(res, 'WWW')

        f = os.path.join(self.backend.files['apps'], "testapp")
        contents = '''
[WWw]
title=Duplicate Web Server
description=Duplicate Web server
ports=80/tcp
'''
        fd = open(f, 'w')
        fd.write(contents)
        fd.close()
        self.backend.profiles = ufw.applications.get_profiles(
                                    self.backend.files['apps'])
        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend.find_application_name,
                              'wWw')

        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend.find_application_name,
                              'nonexistent')

    def test_find_other_position(self):
        '''Test find_other_position()'''
        pr = ufw.frontend.parse_command([] + ['rule', 'allow',
                                         'from', '1234:fff::/64',
                                         'app', 'WWW Secure',
                                         'to', '2345:fff::/64',
                                         'app', 'WWW Full'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])

        pr = ufw.frontend.parse_command(['rule', 'allow', 'WWW'])
        self.backend.rules.append(pr.data['rule'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])

        res = self.backend.find_other_position(2, v6=True)
        self.assertEquals(res, 0)

        res = self.backend.find_other_position(1, v6=False)
        self.assertEquals(res, 2)

        tests.unit.support.check_for_exception(self,
                              ValueError,
                              self.backend.find_other_position,
                              3,
                              True)

        tests.unit.support.check_for_exception(self,
                              ValueError,
                              self.backend.find_other_position,
                              3,
                              False)

        tests.unit.support.check_for_exception(self,
                              ValueError,
                              self.backend.find_other_position,
                              0,
                              False)

        pr = ufw.frontend.parse_command([] + ['rule', 'allow',
                                         'to', '2345:fff::/64',
                                         'app', 'CIFS'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])

        pr = ufw.frontend.parse_command(['rule', 'allow', 'CIFS'])
        self.backend.rules.append(pr.data['rule'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])

        res = self.backend.find_other_position(3, v6=True)
        self.assertEquals(res, 0)

    def test_get_loglevel(self):
        '''Test get_loglevel()'''
        for l in ['off', 'low', 'medium', 'high']:
            self.backend.set_loglevel(l)
            (level, s) = self.backend.get_loglevel()
            self.assertTrue(l in s, "Could not find '%s' in:\n%s" % (l, s))

        self.backend.defaults['loglevel'] = 'nonexistent'
        (level, s) = self.backend.get_loglevel()
        self.assertTrue('unknown' in s, "Could not find 'unknown' in:\n%s" % s)

    def test_set_loglevel(self):
        '''Test set_loglevel()'''
        for ll in ['off', 'on', 'low', 'medium', 'high']:
            self.backend.set_loglevel(ll)
            (level, s) = self.backend.get_loglevel()
            if ll == 'on':
                ll = 'low'
            self.assertTrue(ll in s, "Could not find '%s' in:\n%s" % (ll, s))

        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend.set_loglevel,
                              'nonexistent')

    def test_get_rules_count(self):
        '''Test get_rules_count()'''
        res = self.backend.get_rules_count(v6=False)
        self.assertEquals(res, 0)

        pr = ufw.frontend.parse_command([] + ['rule', 'allow',
                                         'from', '1234:fff::/64',
                                         'app', 'WWW Secure',
                                         'to', '2345:fff::/64',
                                         'app', 'WWW Full'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])

        pr = ufw.frontend.parse_command(['rule', 'allow', 'WWW'])
        self.backend.rules.append(pr.data['rule'])
        pr.data['rule'].set_v6(True)
        self.backend.rules6.append(pr.data['rule'])

        res = self.backend.get_rules_count(v6=False)
        self.assertEquals(res, 1)

        res = self.backend.get_rules_count(v6=True)
        self.assertEquals(res, 2)

    def test_get_rule_by_number(self):
        '''Test get_rule_by_number()'''
        pr1 = ufw.frontend.parse_command(['rule', 'allow', 'WWW'])
        self.backend.rules.append(pr1.data['rule'])

        pr2 = ufw.frontend.parse_command(['rule', 'allow', 'WWW'])
        pr2.data['rule'].set_v6(True)
        self.backend.rules6.append(pr2.data['rule'])

        pr3 = ufw.frontend.parse_command([] + ['rule', 'allow',
                                         'from', '1234:fff::/64',
                                         'app', 'WWW Secure',
                                         'to', '2345:fff::/64',
                                         'app', 'WWW Full'])
        pr3.data['rule'].set_v6(True)
        self.backend.rules6.append(pr3.data['rule'])

        res = self.backend.get_rule_by_number(1)
        self.assertEquals(ufw.common.UFWRule.match(res, pr1.data['rule']), 0)
        self.assertEquals(ufw.common.UFWRule.match(res, pr2.data['rule']), 1)
        self.assertEquals(ufw.common.UFWRule.match(res, pr3.data['rule']), 1)

        res = self.backend.get_rule_by_number(2)
        self.assertEquals(ufw.common.UFWRule.match(res, pr2.data['rule']), 0)
        self.assertEquals(ufw.common.UFWRule.match(res, pr1.data['rule']), 1)
        self.assertEquals(ufw.common.UFWRule.match(res, pr3.data['rule']), 1)

        res = self.backend.get_rule_by_number(3)
        self.assertEquals(ufw.common.UFWRule.match(res, pr3.data['rule']), 0)
        self.assertEquals(ufw.common.UFWRule.match(res, pr1.data['rule']), 1)
        self.assertEquals(ufw.common.UFWRule.match(res, pr2.data['rule']), 1)

        res = self.backend.get_rule_by_number(4)
        self.assertEquals(res, None)

        pr4 = ufw.frontend.parse_command([] + ['rule', 'allow', 'CIFS'])
        self.backend.rules.append(pr4.data['rule'])
        pr4.data['rule'].set_v6(True)
        self.backend.rules6.append(pr4.data['rule'])
        res = self.backend.get_rule_by_number(6)
        self.assertEquals(res, None)
        res = self.backend.get_rule_by_number(4)
        self.assertEquals(ufw.common.UFWRule.match(res, pr4.data['rule']), 1)

    def test_get_matching(self):
        '''Test get_matching()'''
        pr1 = ufw.frontend.parse_command(['rule', 'allow', 'WWW'])
        self.backend.rules.append(pr1.data['rule'])

        pr2 = ufw.frontend.parse_command(['rule', 'deny', 'WWW'])
        self.backend.rules.append(pr2.data['rule'])

        test_rule = pr1.data['rule'].dup_rule()
        res = self.backend.get_matching(test_rule)
        self.assertEquals(len(res), 2)

    def test_set_bad_default_application_policy(self):
        '''Test bad set_default_application_policy()'''
        self.backend.dryrun = False
        for policy in ['alow', 'deny 78&']:
            tests.unit.support.check_for_exception(self,
                                  ufw.common.UFWError,
                                  self.backend.set_default_application_policy,
                                  policy)

    def test_set_default_policy(self):
        '''Test set_default_policy()'''
        # dryrun
        for direction in ['incoming', 'outgoing', 'routed']:
            for policy in ['allow', 'deny', 'reject']:
                res = self.backend.set_default_policy(policy, direction)
                self.assertTrue(policy in res,
                                "Could not find '%s' in:\n%s" % (policy, res))
                self.assertTrue(direction in res,
                                "Could not find '%s' in:\n%s" % (direction,
                                                                 res))

        # no dryrun
        self.backend.dryrun = False
        for direction in ['incoming', 'outgoing']:
            for policy in ['allow', 'deny', 'reject']:
                res = self.backend.set_default_policy(policy, direction)
                self.assertTrue(policy in res,
                                "Could not find '%s' in:\n%s" % (policy, res))
                self.assertTrue(direction in res,
                                "Could not find '%s' in:\n%s" % (direction,
                                                                 res))
                if direction == 'incoming':
                    res = self.backend._get_default_policy("input")
                else:
                    res = self.backend._get_default_policy("output")
                self.assertEquals(res, policy)

        #  no dryrun for routed
        self.backend.dryrun = False
        for forward_enabled in [ False, True ]:
            self._update_sysctl(forward_enabled)
            direction = "routed"
            for policy in ['allow', 'deny', 'reject']:
                res = self.backend.set_default_policy(policy, direction)
                self.assertTrue(policy in res,
                                "Could not find '%s' in:\n%s" % (policy, res))
                self.assertTrue(direction in res,
                                "Could not find '%s' in:\n%s" % (direction,
                                                                 res))
                res = self.backend._get_default_policy("forward",
                                                       check_forward=True)
                if not forward_enabled:
                    policy = "disabled"
                self.assertEquals(res, policy)

    def test_set_default(self):
        '''Test set_default()'''
        self.backend.set_default(self.backend.files['defaults'],
                                 'NEW_INPUT_POLICY',
                                 'accept')
        self.assertEquals(self.backend.defaults['new_input_policy'], 'accept')

    def test_set_bad_default(self):
        '''Test bad set_default_policy()'''
        tests.unit.support.check_for_exception(self,
                                       ufw.common.UFWError,
                                       self.backend.set_default,
                                       self.backend.files['defaults'],
                                       'DEFAULT INPUT_POLICY',
                                       "accept")

        tests.unit.support.check_for_exception(self,
                                       ufw.common.UFWError,
                                       self.backend.set_default,
                                       self.backend.files['defaults'] + \
                                               ".nonexistent",
                                       'DEFAULT_INPUT_POLICY',
                                       "accept")

    def test_get_running_raw(self):
        '''Test get_running_raw()'''
        # dryrun
        for t in ['raw', 'builtins', 'before', 'user', 'after', 'logging']:
            res = self.backend.get_running_raw(t)
            for s in ['iptables', 'ip6tables']:
                self.assertTrue("Checking raw %s" % s in res,
                                "Could not find '%s' in:\n%s" % (s, res))

        # no dryrun
        self.backend.dryrun = False
        for t in ['raw', 'builtins', 'before', 'user', 'after', 'logging']:
            res = self.backend.get_running_raw(t)
            self.assertTrue(t in res, "Could not find '%s' in:\n%s" % \
                            (t, res))

    def test_get_status(self):
        '''Test get_status()'''
        # build up some rules
        cmds_sim = tests.unit.support.get_sample_rule_commands_simple()
        cmds_ext = tests.unit.support.get_sample_rule_commands_extended()

        for cmds in [cmds_sim, cmds_ext]:
            self.backend.rules = []
            self.backend.rules6 = []
            for cmd in cmds:
                pr = ufw.frontend.parse_command(cmd + [])
                action = cmd[1]
                self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                               pr.action))
                if 'rule' in pr.data:
                    if pr.data['rule'].v6:
                        self.backend.rules6.append(pr.data['rule'])
                    else:
                        self.backend.rules.append(pr.data['rule'])

            # dryrun
            self.backend.dryrun = True
            for v in [False, True]:
                for c in [False, True]:
                    res = self.backend.get_status(verbose=v, show_count=c)
                    for s in ['iptables', 'ip6tables']:
                        self.assertTrue("Checking %s" % s in res,
                                        "Could not find '%s' in:\n%s" % (s, res))

            # no dryrun
            self.backend.dryrun = False
            for v in [False, True]:
                for c in [False, True]:
                    res = self.backend.get_status(verbose=v, show_count=c)
                    terms = ['Status: active', 'To']
                    if v:
                        terms += ['Logging: on', 'Default: deny',
                                  'New profiles: skip']
                    if c:
                        terms += '[ 1] '
                    for search in terms:
                        self.assertTrue(search in res,
                                        "Could not find '%s' in:\n%s" % (search,
                                                                     res))

    def test_stop_firewall(self):
        '''Test stop_firewall()'''
        self.backend.stop_firewall()
        self.backend.dryrun = False
        self.backend.stop_firewall()
        # TODO: verify output

    def test_start_firewall(self):
        '''Test start_firewall()'''
        self.backend.start_firewall()
        self.backend.dryrun = False
        self.backend.start_firewall()
        # TODO: verify output

    def test__need_reload(self):
        '''Test _need_reload()'''
        for v6 in [False, True]:
            res = self.backend._need_reload(v6)
            self.backend.dryrun = False
            res = self.backend._need_reload(v6)
            self.assertFalse(res)
            # TODO: verify output

    def test__reload_user_rules(self):
        '''Test _reload_user_rules()'''
        self.backend.defaults['enabled'] = "no"
        self.backend._reload_user_rules()
        self.backend.dryrun = False
        self.backend.defaults['enabled'] = "yes"
        self.backend._reload_user_rules()
        # TODO: verify output

    def test_use_ipv6(self):
        '''Test use_ipv6()'''
        self.backend.defaults['ipv6'] = "yes"
        self.assertTrue(self.backend.use_ipv6())
        self.backend.defaults['ipv6'] = "no"
        self.assertFalse(self.backend.use_ipv6())

    def test__get_defaults(self):
        '''Test _get_defaults()'''
        self.backend._get_defaults()
        for k in ['ipt_modules',
                  'default_output_policy',
                  'default_input_policy',
                  'default_forward_policy',
                  'loglevel',
                  'manage_builtins',
                  'enabled',
                  'ipv6',
                  'default_application_policy']:
            self.assertTrue(k in self.backend.defaults, "Could not find '%s'" \
                                                        % k)

        # Installation defaults are tested elsewhere

        f = self.backend.files['defaults']
        contents = ""
        for line in open(f).readlines():
            if re.search("^DEFAULT_INPUT_POLICY=", line):
                line = "#" + line
            contents += line
        fd = open(f + '.new', 'w')
        fd.write(contents)
        fd.close()
        os.rename(f + '.new', f)

        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend._get_defaults)

        f = self.backend.files['defaults']
        contents = ""
        for line in open(f).readlines():
            if re.search("^#DEFAULT_INPUT_POLICY=", line):
                line = "DEFAULT_INPUT_POLICY=bad" + line
            contents += line
        fd = open(f + '.new', 'w')
        fd.write(contents)
        fd.close()
        os.rename(f + '.new', f)

        tests.unit.support.check_for_exception(self,
                              ufw.common.UFWError,
                              self.backend._get_defaults)

    def test_set_rule(self):
        '''Test set_rule()'''
        self.ui.backend.dryrun = False # keeps the verbosity down
        # TODO: optimize this. We don't need to hit the disk for all of these.
        #       maybe set enabled to 'yes' once for each branch
        self.ui.backend.defaults['enabled'] = "yes"
        cmds_sim = tests.unit.support.get_sample_rule_commands_simple()
        for cmd in cmds_sim:
            pr = ufw.frontend.parse_command(cmd + [])
            action = cmd[1]
            self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                               pr.action))
            if 'rule' in pr.data:
                self.ui.do_action(pr.action, pr.data['rule'], \
                                  pr.data['iptype'], True)
            # TODO: verify output

    def test_update_logging(self):
        '''Test update_logging()'''
        self.backend.defaults['enabled'] = "no"
        self.backend.dryrun = False
        for level in ['off', 'low', 'medium', 'high', 'full']:
            self.backend.defaults['enabled'] = "no"
            self.backend.update_logging(level)
            self.backend.defaults['enabled'] = "yes"
            self.backend.update_logging(level)
            # TODO: verify output

    def test_reset(self):
        '''Test reset()'''
        res = self.backend.reset()
        print(res)

        # we only have 1 second resolution on the backup, so sleep is needed
        time.sleep(1)

        self.backend.dryrun = False
        res = self.backend.reset()
        print(res)
        # TODO: verify output


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            BackendIptablesTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

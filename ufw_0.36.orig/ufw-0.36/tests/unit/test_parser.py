#
# Copyright 2013-2018 Canonical Ltd.
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

import re
import sys
import unittest
import tests.unit.support
import ufw.parser


class ParserTestCase(unittest.TestCase):
    def setUp(self):
        self.parser = ufw.parser.UFWParser()

        # Basic commands
        for i in ['enable', 'disable', 'help', '--help', 'version', \
                  '--version', 'reload', 'reset' ]:
            self.parser.register_command(ufw.parser.UFWCommandBasic(i))

        # Application commands
        for i in ['list', 'info', 'default', 'update']:
            self.parser.register_command(ufw.parser.UFWCommandApp(i))

        # Logging commands
        for i in ['on', 'off', 'low', 'medium', 'high', 'full']:
            self.parser.register_command(ufw.parser.UFWCommandLogging(i))

        # Default commands
        for i in ['allow', 'deny', 'reject']:
            self.parser.register_command(ufw.parser.UFWCommandDefault(i))

        # Status commands ('status', 'status verbose', 'status numbered')
        for i in [None, 'verbose', 'numbered']:
            self.parser.register_command(ufw.parser.UFWCommandStatus(i))

        # Show commands
        for i in ['raw', 'before-rules', 'user-rules', 'after-rules', \
                  'logging-rules', 'builtins', 'listening', 'added']:
            self.parser.register_command(ufw.parser.UFWCommandShow(i))

        # Rule commands
        rule_commands = ['allow', 'limit', 'deny', 'reject', 'insert', \
                         'delete', 'prepend']
        for i in rule_commands:
            self.parser.register_command(ufw.parser.UFWCommandRule(i))
            self.parser.register_command(ufw.parser.UFWCommandRouteRule(i))

    def tearDown(self):
        pass

    def test_ufwcommand_parse_empty(self):
        '''Test UFWCommand.parse([])'''
        c = ufw.parser.UFWCommand('basic', 'status')
        tests.unit.support.check_for_exception(self, ValueError, \
                                                   c.parse,
                                                   [])

    def test_ufwcommand_help(self):
        '''Test UFWCommand.help()'''
        c = ufw.parser.UFWCommand('basic', 'status')
        tests.unit.support.check_for_exception(self, ufw.common.UFWError, \
                                                   c.help,
                                                   [])

    def test_ufwcommand_parse_basic_help(self):
        '''Test parser.parse_command() - help'''
        pr = self.parser.parse_command(['help'])
        search = repr("action='help'\n")
        self.assertTrue(str(pr) == search, "'%s' != '%s'" % (str(pr), search))

    def test_ufwcommand_parse(self):
        '''Test UFWCommand.parse()'''
        c = ufw.parser.UFWCommand('basic', 'status')
        pr = c.parse(['status'])
        self.assertEquals('status', pr.action, "%s != 'status'" % (pr.action))

    def test_ufwcommandbasic_parse_with_arg(self):
        '''Test UFWCommand.parse() - basic with arg'''
        parser = ufw.parser.UFWParser()
        c = ufw.parser.UFWCommandBasic('enable')
        tests.unit.support.check_for_exception(self, ValueError, \
                                                   c.parse,
                                                   ['enable', 'OpenSSH'])

    def test_ufwparser_response(self):
        '''Test UFWParserResponse.str()'''
        cmd = 'rule allow 22'
        pr = self.parser.parse_command(cmd.split())
        s = str(pr)
        search = repr("action='allow',iptype='both'," + \
                      "rule='-p all --dport 22 -j ACCEPT',type='rule'\n")
        self.assertTrue(s == search, "'%s' != '%s'" % (s, search))
        self.assertFalse(pr.dryrun)
        self.assertFalse(pr.force)

        cmd = '--dry-run rule allow 22'
        pr = self.parser.parse_command(cmd.split())
        s = str(pr)
        search = repr("action='allow',iptype='both'," + \
                      "rule='-p all --dport 22 -j ACCEPT',type='rule'\n")
        self.assertTrue(s == search, "'%s' != '%s'" % (s, search))
        self.assertTrue(pr.dryrun)
        self.assertFalse(pr.force)

        cmd = '--force rule allow 22'
        pr = self.parser.parse_command(cmd.split())
        s = str(pr)
        search = repr("action='allow',iptype='both'," + \
                      "rule='-p all --dport 22 -j ACCEPT',type='rule'\n")
        self.assertTrue(s == search, "'%s' != '%s'" % (s, search))
        self.assertTrue(pr.force)

    def test_ufwparser_register_command(self):
        '''Test UFWParser.register_command()'''
        parser = ufw.parser.UFWParser()
        c = ufw.parser.UFWCommandBasic('enable')
        parser.register_command(c)
        self.assertTrue('basic' in parser.commands)
        self.assertTrue('enable' in parser.commands['basic'])

        # Register an already existing command
        tests.unit.support.check_for_exception(self, ufw.common.UFWError, \
                                                   parser.register_command,
                                                   c)

    def test_ufwparser_register_command_none(self):
        '''Test UFWParser.register_command()'''
        parser = ufw.parser.UFWParser()
        c = ufw.parser.UFWCommandBasic('enable')
        c.command = None
        parser.register_command(c)
        self.assertTrue('basic' in parser.commands)
        self.assertTrue('basic' in parser.commands['basic'])

    def test_ufwparser_allowed_command(self):
        '''Test UFWParser.allowed_command()'''
        # Valid commands
        cmd = 'enable'
        res = self.parser.allowed_command('basic', cmd)
        search = cmd.lower()
        self.assertTrue(res == search, "'%s' != '%s'" % (res, search))

        cmd = 'enable'
        res = self.parser.allowed_command('basic', cmd.upper())
        search = cmd.lower()
        self.assertTrue(res == search, "'%s' != '%s'" % (res, search))

        # Invalid commands
        tests.unit.support.check_for_exception(self, ValueError, \
                                                   self.parser.allowed_command,
                                                   'basic', 'nonexistent')

        tests.unit.support.check_for_exception(self, ValueError, \
                                                   self.parser.allowed_command,
                                                   'nonexistent', 'allow')

    def test_ufwcommand_rule_get_command(self):
        '''Test UFWCommand(Route)Rule.get_command()'''
        count = 0
        cmds = tests.unit.support.get_sample_rule_commands_simple()
        cmds += tests.unit.support.get_sample_rule_commands_extended()
        cmds += tests.unit.support.get_sample_rule_commands_extended(v6=True)
        cmds += [
                 ['rule', 'reject', 'from', 'any', 'app', 'Apache'],
                 ['rule', 'reject', 'from', 'any', 'port', 'smtp'],
                 ['route', 'reject', 'from', 'any', 'app', 'Apache'],
                 ['route', 'reject', 'from', 'any', 'port', 'smtp'],
                 ['route', 'allow', 'out', 'on', 'eth1', 'in', 'on', 'eth0'],
                ]
        errors = []

        for cmd in cmds:
            count += 1
            #print(" ".join(cmd))
            # Note, parser.parse_command() modifies its arg, so pass a copy of
            # the cmd, not a reference
            pr = self.parser.parse_command(cmd + [])
            if cmd[0] == 'rule':
                res = ufw.parser.UFWCommandRule.get_command(pr.data['rule'])
            else:
                res = ufw.parser.UFWCommandRouteRule.get_command(
                        pr.data['rule'])

            # First, feed the res rule into parse() (we need to split the
            # string but preserve quoted substrings
            if sys.version_info[0] < 3:
                test_cmd = [cmd[0]] + \
                           [p.strip("'").encode('utf-8') for p in re.split("( |'.*?')",
                                                           res) if p.strip()]
            else:
                test_cmd = [cmd[0]] + \
                           [p.strip("'") for p in re.split("( |'.*?')",
                                                           res) if p.strip()]
            try:
                self.parser.parse_command(test_cmd + [])
            except ufw.common.UFWError:
                self.assertTrue(False,
                                "get_command() returned invalid rule:\n" + \
                                " orig=%s\n pr.data['rule']=%s\n result=%s" % \
                                (cmd, pr.data['rule'], test_cmd))

            # Next, verify the output is what we expect. We need to massage the
            # cmd_compare output a bit first since many rules can be expressed
            # using the same syntax. Eg, these are all the same rule and
            # get_command() typically outputs the simplest form:
            #  ufw allow 22
            #  ufw allow in 22
            #  ufw allow to any port 22
            #  ufw allow from any to any port 22
            #  ufw rule allow 22
            #  ufw rule allow in 22
            #  ufw rule allow to any port 22
            #  ufw rule allow from any to any port 22

            # Note, cmd_compare contains the rules we get from
            # tests.unit.support.get_sample_rule_commands*
            cmd_compare = []

            # store off command so we can add it at the end after the massaging
            comment = ""

            if 'comment' in cmd:
                comment_idx = cmd.index('comment')
                comment = cmd[comment_idx + 1]
                del cmd[comment_idx + 1]
                del cmd[comment_idx]

            for i in cmd:
                if ' ' in i:  # quote anything with a space for comparisons
                    cmd_compare.append("'%s'" % i)
                else:
                    cmd_compare.append(i)

            # remove 'in' on rules without an interface
            if 'in' in cmd_compare and 'on' not in cmd_compare:
                cmd_compare.remove('in')

            # use '1/tcp' instead of 'tcpmux' for simple rules and
            # 'port 1 proto tcp' for extended
            if 'tcpmux' in cmd_compare:
                if 'to' in cmd_compare or 'from' in cmd_compare:  # extended
                    cmd_compare[cmd_compare.index('tcpmux')] = '1'
                    if 'proto' not in cmd_compare:
                        cmd_compare.append('proto')
                        cmd_compare.append('tcp')
                    if 'tcpmux' in cmd_compare:  # can have 2 in extended rules
                        cmd_compare[cmd_compare.index('tcpmux')] = '1'
                else:  # simple
                    cmd_compare[cmd_compare.index('tcpmux')] = '1/tcp'

            # use '21/udp' instead of 'fsp' for simple rules and
            # 'port 21 proto udp' for extended
            if 'fsp' in cmd_compare:
                if 'to' in cmd_compare or 'from' in cmd_compare:  # extended
                    cmd_compare[cmd_compare.index('fsp')] = '21'
                    if 'proto' not in cmd_compare:
                        cmd_compare.append('proto')
                        cmd_compare.append('udp')
                    if 'fsp' in cmd_compare:  # can have 2 in extended rules
                        cmd_compare[cmd_compare.index('fsp')] = '21'
                else:  # simple rule
                    cmd_compare[cmd_compare.index('fsp')] = '21/udp'

            # use 'port 25 proto tcp' in extended rules
            if 'smtp' in cmd_compare and 'proto' not in cmd_compare:
                cmd_compare[cmd_compare.index('smtp')] = '25'
                cmd_compare.append('proto')
                cmd_compare.append('tcp')

            # remove 'from any' clause when used without port or app
            if 'from' in cmd_compare and \
               cmd_compare[cmd_compare.index('from') + 1] == 'any' and \
               (len(cmd_compare) - 2 == cmd_compare.index('from') or \
                (cmd_compare.index('from') + 2 < len(cmd_compare) and \
                 cmd_compare[cmd_compare.index('from') + 2] != 'port' and \
                 cmd_compare[cmd_compare.index('from') + 2] != 'app')):
                del cmd_compare[cmd_compare.index('from') + 1]
                cmd_compare.remove('from')

            # remove 'to any' clause when used without port or app when 'from'
            # 'proto' or 'on' is present ('from' will not be 'any' because of
            # above)
            if ('from' in cmd_compare or 'proto' in cmd_compare or \
                'on' in cmd_compare) and 'to' in cmd_compare and \
               cmd_compare[cmd_compare.index('to') + 1] == 'any' and \
               (len(cmd_compare) - 2 == cmd_compare.index('to') or \
                (cmd_compare.index('to') + 2 < len(cmd_compare) and \
                 cmd_compare[cmd_compare.index('to') + 2] != 'port' and \
                 cmd_compare[cmd_compare.index('to') + 2] != 'app')):
                del cmd_compare[cmd_compare.index('to') + 1]
                cmd_compare.remove('to')

            # remove 'to any' if no 'from' clause (ie, convert extended to
            # simple)
            if 'to' in cmd_compare and 'from' not in cmd_compare and \
               cmd_compare[cmd_compare.index('to') + 1] == 'any' and \
               cmd_compare.index('to') + 2 < len(cmd_compare) and \
               'on' not in cmd_compare:
                if 'port' in cmd_compare:
                    port = "%s" % cmd_compare[cmd_compare.index('port') + 1]
                    if 'proto' in cmd_compare:
                        port += "/%s" % \
                                cmd_compare[cmd_compare.index('proto') + 1]
                    del cmd_compare[cmd_compare.index('proto') + 1]
                    cmd_compare.remove('proto')
                    del cmd_compare[cmd_compare.index('port') + 1]
                    cmd_compare.remove('port')
                    del cmd_compare[cmd_compare.index('to') + 1]
                    cmd_compare.remove('to')
                    cmd_compare.append(port)
                elif 'app' in cmd_compare:
                    del cmd_compare[cmd_compare.index('to') + 2]
                    del cmd_compare[cmd_compare.index('to') + 1]
                    cmd_compare.remove('to')

            # add back 'to any' if have no 'to', 'from' or 'on' and have either
            # proto or the last entry in cmd_compare indicates generic extended
            # rule
            generics = ['in', 'out', 'allow', 'deny', 'reject', 'limit']
            if 'to' not in cmd_compare and 'from' not in cmd_compare and \
                    'on' not in cmd_compare and ('proto' in cmd_compare or \
                    cmd_compare[-1].startswith('log') or \
                    cmd_compare[-1] in generics):
                if 'proto' in cmd_compare:
                    cmd_compare.insert(cmd_compare.index('proto'), "to")
                    cmd_compare.insert(cmd_compare.index('proto'), "any")
                else:
                    cmd_compare.append("to")
                    cmd_compare.append("any")

            # flip 'in on' and 'out on' for route rules ('in on' is always
            # listed first
            if cmd_compare[0] == 'route' and \
                    'out' in cmd_compare and 'in' in cmd_compare and \
                    cmd_compare.index('out') < cmd_compare.index('in'):
                tmp_out_idx = cmd_compare.index('out')
                tmp_outif = cmd_compare[tmp_out_idx + 2]
                tmp_in_idx = cmd_compare.index('in')
                tmp_inif = cmd_compare[tmp_in_idx + 2]
                cmd_compare[tmp_out_idx] = 'in'
                cmd_compare[tmp_out_idx + 2] = tmp_inif
                cmd_compare[tmp_in_idx] = 'out'
                cmd_compare[tmp_in_idx + 2] = tmp_outif

            # add comment back
            if comment != "":
                cmd_compare.append('comment')
                compare_str = " ".join(cmd_compare)
                if sys.version_info[0] < 3:
                    compare_str += " '%s'" % comment.decode('utf-8')
                else:
                    compare_str += " '%s'" % comment
                cmd_compare.append(comment)
            else:
                compare_str = " ".join(cmd_compare)
            if "%s %s" % (cmd[0], res) != compare_str:
                errors.append(" \"%s %s\" != \"%s\" (orig=%s)" % (cmd[0], res,
                    compare_str, cmd))

            #print("Result: rule %s" % res)

        self.assertEquals(len(errors), 0,
                          "Rules did not match:\n%s\n(%d of %d)" % \
                          ("\n".join(errors), len(errors), count))
        print("%d rules checked" % count)

    def test_simple_parse(self):
        '''Test simple rule syntax'''
        count = 0
        cmds = tests.unit.support.get_sample_rule_commands_simple()
        for cmd in cmds:
            count += 1
            #print(" ".join(cmd))
            # Note, parser.parse_command() modifies its arg, so pass a copy of
            # the cmd, not a reference
            pr = self.parser.parse_command(cmd + [])

            # TODO: more tests here by sending the cmd and the pr to a helper
            action = cmd[1]
            self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                               pr.action))

            del_cmd = cmd + []
            del_cmd.insert(1, 'delete')
            #print(" ".join(del_cmd))
            # Note, parser.parse_command() modifies its arg, so pass a copy of
            # the del_cmd, not a reference
            pr = self.parser.parse_command(del_cmd + [])

            # TODO: more tests here by sending the cmd and the pr to a helper
            action = del_cmd[2]
            self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                               pr.action))
            ins_cmd = cmd + []
            ins_cmd.insert(1, 'insert')
            ins_cmd.insert(2, '1')
            #print(" ".join(ins_cmd))
            # Note, parser.parse_command() modifies its arg, so pass a copy of
            # the del_cmd, not a reference
            pr = self.parser.parse_command(ins_cmd + [])

            # TODO: more tests here by sending the cmd and the pr to a helper
            action = ins_cmd[3]
            self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                               pr.action))
        print("%d rules checked" % count)

    def test_misc_rules_parse(self):
        '''Test rule syntax - miscellaneous'''
        cmds = [
                ['delete', 'allow', '22'],
                ['deny', 'from', 'any', 'port', 'domain', 'to', 'any', \
                 'port', 'tftp'],
                ['allow', 'to', 'any', 'proto', 'gre'],
                ['deny', 'to', 'any', 'proto', 'ipv6'],
                ['allow', 'to', 'any', 'proto', 'igmp'],
                ['reject', 'to', 'any', 'proto', 'esp'],
                ['deny', 'to', '224.0.0.1', 'proto', 'igmp'],
                ['deny', 'in', 'on', 'eth0', 'to', '224.0.0.1', 'proto', \
                 'igmp'],
                ['allow', 'in', 'on', 'eth0', 'to', '192.168.0.1', 'proto', \
                 'gre'],
                ['deny', 'to', 'any', 'proto', 'ah'],
                ['allow', 'out', 'on', 'br_lan'],
               ]
        count = 0
        for rtype in ['route', 'rule']:
            if rtype == 'rule':
                cmds.append(['delete', '1'])
            for cmd in cmds:
                #print(" ".join(cmd))
                count += 1
                # Note, parser.parse_command() modifies its arg, so pass a copy of
                # the cmd, not a reference
                self.parser.parse_command([rtype] + cmd)

    def test_rule_bad_syntax(self):
        '''Test rule syntax - bad'''
        cmds = [
                (['rule', 'insert', '1', 'allow'], ValueError),
                (['rule', 'insert', 'a', 'allow', '22'], ufw.common.UFWError),
                (['rule', 'insert', '0', 'allow', '22'], ufw.common.UFWError),
                (['rule', 'prepend', 'allow'], ValueError),
                (['rule', 'allow'], ValueError),
                (['rule'], ValueError),
                (['rule', 'allow', '22', 'in', 'on', 'eth0'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'in', 'eth0', '22'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'on', 'eth0', '22', 'log'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'on', 'eth0', '22', 'log-all'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'on', 'eth0', 'log', 'to', 'any', \
                  'port', '22', 'from', 'any', 'port', '123', 'proto', 'udp', \
                  'extra'], ValueError),
                (['rule', 'allow', '22/udp/p'], ufw.common.UFWError),
                (['rule', 'allow', '22:2e'], ufw.common.UFWError),
                (['rule', 'allow', '22/ipv6'], ufw.common.UFWError),
                (['rule', 'reject', 'in', 'on', 'eth0', 'port', '22'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', '22'], ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', 'to', '22'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', 'proto', 'nope'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'on', '!eth0', 'to', 'any'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'out', 'on', 'eth0:0', 'to', 'any'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'on', '$eth', 'to', 'any'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'in', 'eth0', 'to', 'any'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'from', 'bad_address'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', 'bad_address'], ufw.common.UFWError),
                (['rule', 'badcmd', 'to', 'any'], ValueError),
                (['rule', 'allow', 'port', '22'], ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', 'port', '22_23'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', 'port', '22:_23'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', 'port', '65536'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', '::1', 'from', '127.0.0.1'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', 'any', 'port', 'nonexistent'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'from', 'any', 'port', 'nonexistent',
                  'proto', 'any'], ufw.common.UFWError),
                (['rule', 'allow', 'from', 'any', 'port', 'tftp', 'to', 'any',
                 'port', 'smtp'], ufw.common.UFWError),
                (['rule', 'deny', 'from', 'any', 'port', 'smtp', 'to', 'any',
                 'port', 'tftp', 'proto', 'any'], ufw.common.UFWError),
                (['rule', 'allow', 'nope', 'any', 'to', 'any'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', 'any', 'port', 'tftp',
                  'proto', 'tcp'], ufw.common.UFWError),
                (['rule', 'deny', 'to', '::1', 'proto', 'ipv6'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', '::1', 'proto', 'igmp'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', 'any', 'port', '22', 'proto', 'ipv6'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', 'any', 'port', '22', 'proto', 'igmp'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', 'any', 'port', '22', 'proto', 'esp'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', 'any', 'port', '22', 'proto', 'ah'],
                 ufw.common.UFWError),
                (['rule', 'deny', 'to', 'any', 'port', '22', 'proto', 'gre'],
                 ufw.common.UFWError),
                (['rule', 'allow', 'to', '192.168.0.0/16', 'app', 'Samba',
                  'from', '192.168.0.0/16', 'port', 'tcpmux'],
                  ufw.common.UFWError),
                (['route', 'badcmd', 'to', 'any'], ValueError),
                (['route', 'allow', 'in', '22'], ufw.common.UFWError),
                (['route', 'deny', 'out', '22'], ufw.common.UFWError),
                (['route', 'allow', 'to', '192.168.0.0/16', 'app', 'Samba',
                  'from', '192.168.0.0/16', 'port', 'tcpmux'],
                  ufw.common.UFWError),
                (['rule', 'allow', '22', 'comment', "foo'bar"], ValueError),
                (['rule', 'allow', '22', 'comment'], ufw.common.UFWError),
                (['route', 'delete', '1'], ufw.common.UFWError),
               ]
        for cmd, exception in cmds:
            #print(" ".join(cmd))
            # Note, parser.parse_command() modifies its arg, so pass a copy of
            # the cmd, not a reference
            tests.unit.support.check_for_exception(self, exception,
                                                   self.parser.parse_command,
                                                   cmd + [])

    def test_extended_parse(self):
        '''Test extended rule syntax'''
        count = 0
        cmds = tests.unit.support.get_sample_rule_commands_extended()
        cmds6 = tests.unit.support.get_sample_rule_commands_extended(v6=True)
        for cmd in cmds + cmds6:
            count += 1
            #print(" ".join(cmd))
            # Note, parser.parse_command() modifies its arg, so pass a copy of
            # the cmd, not a reference
            pr = self.parser.parse_command(cmd + [])

            # TODO: more tests here by sending the cmd and the pr to a helper
            action = cmd[1]
            self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                               pr.action))

        print("%d rules checked" % count)

    def test_simple_bad_numeric_port(self):
        '''Test simple bad numeric port'''
        for port in ['-1', '1000000']:
            c = ['rule', 'allow', port]
            tests.unit.support.check_for_exception(self, ufw.common.UFWError, \
                                                   self.parser.parse_command,
                                                   c)

    def test_bad_simple_action(self):
        '''Test bad simple action'''
        for action in ['allw', 'eny', 'nonexistent']:
            c = ['rule', action, '22']
            tests.unit.support.check_for_exception(self, ValueError, \
                                                   self.parser.parse_command,
                                                   c)

    def test_delete_bad_simple_action(self):
        '''Test delete bad simple action'''
        for action in ['allw', 'eny', 'nonexistent']:
            c = ['rule', 'delete', action, '22']
            tests.unit.support.check_for_exception(self, ValueError, \
                                                   self.parser.parse_command,
                                                   c)

    def test_bad_simple_action_with_direction(self):
        '''Test bad simple action with direction'''
        for dir in ['ina', 'ou']:
            c = ['rule', 'allow', dir, '22']
            #self.parser.parse_command(c)
            tests.unit.support.check_for_exception(self, ufw.common.UFWError, \
                                                   self.parser.parse_command,
                                                   c)

        c = ['rule', 'allow', 5, '22']
        tests.unit.support.check_for_exception(self, AttributeError, \
                                               self.parser.parse_command,
                                               c)

    def test_route_delete_num(self):
        '''Test route delete NUM'''
        c = ['route', 'delete', '1']
        tests.unit.support.check_for_exception(self, ufw.common.UFWError, \
                                               self.parser.parse_command,
                                               c)

    def test_app_parse(self):
        '''Test UFWCommandApp.parse()'''
        cmds = [
                (['app', 'list'], None),
                (['app', 'info', 'WWW'], None),
                (['app', 'info', 'WWW Full'], None),
                (['app', 'info', 'Samba'], None),
                (['app', 'info', 'DNS'], None),
                (['app', 'update', 'WWW'], None),
                (['app', 'update', '--add-new', 'WWW'], None),
                (['app', 'default', 'allow'], None),
                (['app', 'default', 'deny'], None),
                (['app', 'default', 'reject'], None),
                (['app', 'default', 'skip'], None),
                (['notapp'], ValueError),
                (['app', 'default'], ValueError),
                (['app', 'list', 'extra args'], ValueError),
                (['app', 'info'], ValueError),
                (['app', 'default'], ValueError),
                (['app', 'default', 'nonexistent'], ValueError),
               ]
        for cmd, exception in cmds:
            #print(" ".join(cmd))

            if exception is not None:
                c = ufw.parser.UFWCommandApp(" ".join(cmd))
                tests.unit.support.check_for_exception(self, exception,
                                                       c.parse,
                                                       cmd + [])
            else:
                # Note, parser.parse_command() modifies its arg, so pass a copy
                # of the cmd, not a reference
                pr = self.parser.parse_command(cmd + [])

                # TODO: more tests here by sending the cmd and the pr to a
                # helper
                action = cmd[1]
                if action == 'update' and cmd[2] == '--add-new':
                    action = 'update-with-new'
                elif action == 'default':
                    action = "default-%s" % cmd[2]
                self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                                   pr.action))

    def test_default_parse(self):
        '''Test UFWCommandDefault.parse()'''
        cmds = [
                (['default', 'reject'], None),
                (['default', 'deny', 'incoming'], None),
                (['default', 'allow', 'outgoing'], None),
                (['default', 'deny', 'routed'], None),
                (['default'], ValueError),
                (['default', 'nonexistent'], ValueError),
                (['default', 'nonexistent', 'allow'], ValueError),
                (['default', 'incoming', 'allow'], ValueError),
                (['default', 'routed', 'deny'], ValueError),
               ]
        for cmd, exception in cmds:
            #print(" ".join(cmd))

            if exception is not None:
                c = ufw.parser.UFWCommandDefault(" ".join(cmd))
                tests.unit.support.check_for_exception(self, exception,
                                                       c.parse,
                                                       cmd + [])
            else:
                # Note, parser.parse_command() modifies its arg, so pass a copy
                # of the cmd, not a reference
                pr = self.parser.parse_command(cmd + [])

                # TODO: more tests here by sending the cmd and the pr to a
                # helper
                action = cmd[1]
                pol = "incoming"
                if len(cmd) >= 3:
                    pol = cmd[2]
                action = "default-%s-%s" % (cmd[1], pol)
                self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                                   pr.action))

    def test_logging_parse(self):
        '''Test UFWCommandLogging.parse()'''
        cmds = [
                (['logging', 'on'], None),
                (['logging', 'off'], None),
                (['logging', 'low'], None),
                (['logging', 'medium'], None),
                (['logging', 'high'], None),
                (['logging', 'full'], None),
                (['logging'], ValueError),
                (['logging', 'nonexistent'], ValueError),
               ]
        for cmd, exception in cmds:
            #print(" ".join(cmd))

            if exception is not None:
                c = ufw.parser.UFWCommandLogging(" ".join(cmd))
                tests.unit.support.check_for_exception(self, exception,
                                                       c.parse,
                                                       cmd + [])
            else:
                # Note, parser.parse_command() modifies its arg, so pass a copy
                # of the cmd, not a reference
                pr = self.parser.parse_command(cmd + [])

                # TODO: more tests here by sending the cmd and the pr to a
                # helper
                action = "logging-%s" % (cmd[1])
                if cmd[1] != "on" and cmd[1] != "off":
                    action = "logging-on_%s" % (cmd[1])
                self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                                   pr.action))

    def test_status_parse(self):
        '''Test UFWCommandStatus.parse()'''
        cmds = [
                (['status'], None),
                (['status', 'verbose'], None),
                (['status', 'numbered'], None),
                (['status', 'bad'], ValueError),
               ]
        for cmd, exception in cmds:
            #print(" ".join(cmd))

            if exception is not None:
                c = ufw.parser.UFWCommandStatus(" ".join(cmd))
                tests.unit.support.check_for_exception(self, exception,
                                                       c.parse,
                                                       cmd + [])
            else:
                # Note, parser.parse_command() modifies its arg, so pass a copy
                # of the cmd, not a reference
                pr = self.parser.parse_command(cmd + [])

                # TODO: more tests here by sending the cmd and the pr to a
                # helper
                action = cmd[0]
                if len(cmd) > 1:
                    action = "%s-%s" % (cmd[0], cmd[1])
                self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                                   pr.action))

    def test_show_parse(self):
        '''Test UFWCommandShow.parse()'''
        cmds = [
                (['show', 'raw'], None, "show-raw"),
                (['show', 'before-rules'], None, "show-before"),
                (['show', 'after-rules'], None, "show-after"),
                (['show', 'user-rules'], None, "show-user"),
                (['show', 'logging-rules'], None, "show-logging"),
                (['show', 'builtins'], None, "show-builtins"),
                (['show', 'listening'], None, "show-listening"),
                (['show', 'added'], None, "show-added"),
                (['show'], ValueError, None),
                (['show', 'bad'], ValueError, None),
               ]
        for cmd, exception, action in cmds:
            #print(" ".join(cmd))

            if exception is not None:
                c = ufw.parser.UFWCommandShow(" ".join(cmd))
                tests.unit.support.check_for_exception(self, exception,
                                                       c.parse,
                                                       cmd + [])
            else:
                # Note, parser.parse_command() modifies its arg, so pass a copy
                # of the cmd, not a reference
                pr = self.parser.parse_command(cmd + [])

                # TODO: more tests here by sending the cmd and the pr to a
                # helper
                self.assertEquals(action, pr.action, "%s != %s" % (action, \
                                                                   pr.action))


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            ParserTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

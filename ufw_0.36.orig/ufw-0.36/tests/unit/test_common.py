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
import ufw.common


class CommonTestCase(unittest.TestCase):
    def setUp(self):
        self.rules = {
                "any":  ufw.common.UFWRule("allow", "any"),
                "ipv6": ufw.common.UFWRule("deny", "ipv6"),
                "tcp":  ufw.common.UFWRule("limit", "tcp"),
                "udp":  ufw.common.UFWRule("allow", "udp"),
                "reject-tcp":  ufw.common.UFWRule("reject", "tcp"),
                "reject-udp":  ufw.common.UFWRule("reject", "udp"),
                "full-any":  ufw.common.UFWRule("allow", "any",
                    dport="123", dst="10.0.0.1", sport="124",
                    src="10.0.0.2", direction="in"),
                "full-ipv6": ufw.common.UFWRule("deny", "ipv6",
                    dport="123", dst="10.0.0.1", sport="124",
                    src="10.0.0.2", direction="in"),
                "full-tcp":  ufw.common.UFWRule("limit", "tcp",
                    dport="123", dst="10.0.0.1", sport="124",
                    src="10.0.0.2", direction="out"),
                "full-udp":  ufw.common.UFWRule("reject", "udp",
                    dport="123", dst="10.0.0.1", sport="124",
                    src="10.0.0.2", direction="out"),
                "dapp":  ufw.common.UFWRule("allow", "any"),
                "sapp":  ufw.common.UFWRule("deny", "any"),
                "app-both":  ufw.common.UFWRule("deny", "any"),
                "multi-dport": ufw.common.UFWRule("allow", "tcp",
                    dport="80,443,8080:8090"),
                "multi-sport": ufw.common.UFWRule("allow", "tcp",
                    sport="80,443,8080:8090"),
                "multi-both": ufw.common.UFWRule("allow", "tcp",
                    dport="80,443,8080:8090", sport="23"),
                "log":  ufw.common.UFWRule("allow", "tcp", dport="22"),
                "log-all":  ufw.common.UFWRule("allow", "tcp", dport="22"),
               }
        self.rules['dapp'].dapp = "Apache"
        self.rules['dapp'].dport = "80"
        self.rules['dapp'].proto = "tcp"

        self.rules['sapp'].sapp = "Apache"
        self.rules['sapp'].sport = "80"
        self.rules['sapp'].proto = "tcp"

        self.rules['app-both'].dapp = "Apache"
        self.rules['app-both'].dport = "80"
        self.rules['app-both'].proto = "tcp"
        self.rules['app-both'].sapp = "Apache"
        self.rules['app-both'].sport = "80"
        self.rules['app-both'].proto = "tcp"

        self.rules['log'].set_logtype("log")
        self.rules['log-all'].set_logtype("log-all")

    def tearDown(self):
        self.rules = None

    def test_ufwerror(self):
        '''Test UFWError'''
        try:
            raise ufw.common.UFWError("test")
        except ufw.common.UFWError as e:
            self.assertEquals(e.value, "test", "'%s' != 'test'" % e.value)
            return
        self.assertTrue(False, "Did not raise an error")

    def test_ufwerror_str(self):
        '''Test UFWError.str()'''
        e = ufw.common.UFWError("test")
        search = repr("test")
        self.assertEquals(str(e), search, "'%s' != 'test'" % search)

    def test__init_(self):
        '''Test UFWRule.__init__()'''
        r = ufw.common.UFWRule("allow", "tcp", "22")
        self.assertEquals(r.action, "allow")
        self.assertEquals(r.protocol, "tcp")
        self.assertEquals(r.dport, "22")

        tests.unit.support.check_for_exception(self, ufw.common.UFWError,
                                               ufw.common.UFWRule,
                                               "allow",
                                               "nonexistent",
                                               "22")

    def test__get_attrib(self):
        '''Test _get_attrib()'''
        res = self.rules["any"]._get_attrib()
        search = "'-p all -j ACCEPT', action=allow, comment=, dapp=, " + \
                 "direction=in, dport=any, dst=0.0.0.0/0, forward=False, " + \
                 "interface_in=, interface_out=, logtype=, multi=False, " + \
                 "position=0, protocol=any, remove=False, sapp=, " + \
                 "sport=any, src=0.0.0.0/0, updated=False, v6=False"
        self.assertEquals(res, search, "'%s' != '%s'" % (res, search))

    def test_dup_rule(self):
        '''Test dup_rule()'''
        r = self.rules["any"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.match(r, self.rules["any"]), 0)

    def test_format_rule(self):
        '''Test format_rule()'''
        s = str(self.rules["any"])
        self.assertEquals(s, "-p all -j ACCEPT")

        s = str(self.rules["app-both"])
        self.assertEquals(s, "-p all --dport 80 --sport 80 -j DROP " + \
                             "-m comment --comment 'dapp_Apache,sapp_Apache'")

        s = str(self.rules["dapp"])
        self.assertEquals(s, "-p all --dport 80 -j ACCEPT " + \
                             "-m comment --comment 'dapp_Apache'")

        s = str(self.rules["full-any"])
        self.assertEquals(s, "-p all -d 10.0.0.1 --dport 123 " + \
                             "-s 10.0.0.2 --sport 124 -j ACCEPT")

        s = str(self.rules["full-ipv6"])
        self.assertEquals(s, "-p ipv6 -d 10.0.0.1 --dport 123 " + \
                             "-s 10.0.0.2 --sport 124 -j DROP")

        s = str(self.rules["full-tcp"])
        self.assertEquals(s, "-p tcp -d 10.0.0.1 --dport 123 " + \
                             "-s 10.0.0.2 --sport 124 -j LIMIT")

        s = str(self.rules["full-udp"])
        self.assertEquals(s, "-p udp -d 10.0.0.1 --dport 123 " + \
                             "-s 10.0.0.2 --sport 124 -j REJECT")

        s = str(self.rules["ipv6"])
        self.assertEquals(s, "-p ipv6 -j DROP")

        s = str(self.rules["log"])
        self.assertEquals(s, "-p tcp --dport 22 -j ACCEPT_log")

        s = str(self.rules["log-all"])
        self.assertEquals(s, "-p tcp --dport 22 -j ACCEPT_log-all")
        r = self.rules["log-all"].dup_rule()
        r.set_action("deny_log-all")
        s = str(r)
        self.assertEquals(s, "-p tcp --dport 22 -j DROP_log-all")

        s = str(self.rules["multi-both"])
        self.assertEquals(s, "-p tcp -m multiport " + \
                             "--dports 80,443,8080:8090 " + \
                             "-m multiport --sports 23 -j ACCEPT")

        s = str(self.rules["multi-dport"])
        self.assertEquals(s, "-p tcp -m multiport " + \
                             "--dports 80,443,8080:8090 -j ACCEPT")

        s = str(self.rules["multi-sport"])
        self.assertEquals(s, "-p tcp -m multiport " + \
                             "--sports 80,443,8080:8090 -j ACCEPT")

        s = str(self.rules["reject-tcp"])
        self.assertEquals(s, "-p tcp -j REJECT --reject-with tcp-reset")

        s = str(self.rules["reject-udp"])
        self.assertEquals(s, "-p udp -j REJECT")

        s = str(self.rules["sapp"])
        self.assertEquals(s, "-p all --sport 80 -j DROP " + \
                             "-m comment --comment 'sapp_Apache'")

        s = str(self.rules["tcp"])
        self.assertEquals(s, "-p tcp -j LIMIT")

        s = str(self.rules["udp"])
        self.assertEquals(s, "-p udp -j ACCEPT")

    def test_set_action(self):
        '''Test set_action()'''
        r = self.rules["any"]
        for action in ['allow', 'deny', 'reject', 'limit']:
            r.set_action(action)
            self.assertEquals(action, r.action, "%s != %s" %
                              (action, r.action))

    def test_set_port(self):
        '''Test set_port()'''
        rule = self.rules["any"]
        for loc in ['dst', 'src']:
            for port in ['any',
                         '1',
                         '22',
                         '1023',
                         '1024',
                         '1025',
                         '65535',
                         '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15',
                         '80,443,8080:8090',
                         '22:25']:
                r = rule.dup_rule()
                r.set_port(port, loc)
                if loc == 'dst':
                    self.assertEquals(port, r.dport, "%s != %s" % (port,
                                                                   r.dport))
                else:
                    self.assertEquals(port, r.sport, "%s != %s" % (port,
                                                                   r.sport))

        r = self.rules["dapp"].dup_rule()
        r.dapp = "Apache"
        r.set_port("Apache", "dst")
        self.assertEquals(r.dapp, r.dport, "%s != %s" % (r.dapp, r.dport))

        r = self.rules["sapp"].dup_rule()
        r.sapp = "Apache"
        r.set_port("Apache", "src")
        self.assertEquals(r.sapp, r.sport, "%s != %s" % (r.sapp, r.sport))

    def test_set_port_bad(self):
        '''Test set_port() - bad'''
        rule = self.rules["any"]
        for loc in ['dst', 'src']:
            for port in ['an',
                         '0',
                         ',',
                         '',
                         ' ',
                         22,
                         '65536',
                         ',443,8080:8090',
                         '443:8080:8090',
                         '0:65536',
                         '2:1',
                         '80,',
                         '80,443,8080:',
                         ':8090',
                         '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16',
                        ]:
                r = rule.dup_rule()
                e = ufw.common.UFWError
                if port == 22:
                    e = TypeError
                tests.unit.support.check_for_exception(self,
                                                       e,
                                                       r.set_port,
                                                       port,
                                                       loc)

    def test_set_protocol(self):
        '''Test set_protocol()'''
        r = self.rules["any"]
        for proto in ['any', 'tcp', 'udp', 'ipv6', 'esp', 'ah']:
            r.set_protocol(proto)
            self.assertEquals(proto, r.protocol, "%s != %s" %
                              (proto, r.protocol))

    def test_set_protocol_bad(self):
        '''Test set_protocol() - bad'''
        r = self.rules["any"]
        for proto in ['an', 'cp', 'up', 'nonexistent']:
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   r.set_protocol,
                                                   proto)

    def test__fix_anywhere(self):
        '''Test _fix_anywhere()'''
        x = self.rules["any"].dup_rule()
        x.set_v6(False)
        x._fix_anywhere()
        search = "0.0.0.0/0"
        self.assertEquals(x.dst, search, "'%s' != '%s'" % (x.dst, search))

        y = x.dup_rule()
        y.set_v6(True)
        y._fix_anywhere()
        search = "::/0"
        self.assertEquals(y.dst, search, "'%s' != '%s'" % (y.dst, search))

    def test_set_v6(self):
        '''Test set_v6()'''
        r = self.rules["any"]
        for ipv6 in [True, False]:
            r.set_v6(ipv6)
            self.assertEquals(ipv6, r.v6, "%s != %s" %
                              (ipv6, r.v6))

    def test_set_src(self):
        '''Test set_src()'''
        r = self.rules["any"]
        for src in ["10.0.0.3"]:
            r.set_src(src)
            self.assertEquals(src, r.src, "%s != %s" %
                              (src, r.src))

    def test_set_src_bad(self):
        '''Test set_src() - bad'''
        r = self.rules["any"]
        for src in ["10.0.0.", "10..0.0.3"]:
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   r.set_src,
                                                   src)

    def test_set_dst(self):
        '''Test set_dst()'''
        r = self.rules["any"]
        for dst in ["10.0.0.3"]:
            r.set_dst(dst)
            self.assertEquals(dst, r.dst, "%s != %s" %
                              (dst, r.dst))

    def test_set_dst_bad(self):
        '''Test set_dst() - bad'''
        r = self.rules["any"]
        for dst in ["10.0.0.", "10..0.0.3"]:
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   r.set_dst,
                                                   dst)

    def test_set_interface(self):
        '''Test set_interface()'''
        r = self.rules["any"]
        for if_type in ["in", "out"]:
            for interface in ["eth0", "wlan1", "br_lan", "virbr0-nic", "0eth",
                              "eth0_1", "eth0.1", "foo%bar", "foo@Bar",
                              "=foo", "vethQNIAKF@if18", "lo"]:
                r.set_interface(if_type, interface)
                if if_type == "in":
                    self.assertEquals(interface, r.interface_in, "%s != %s" %
                                      (interface, r.interface_in))
                else:
                    self.assertEquals(interface, r.interface_out, "%s != %s" %
                                      (interface, r.interface_out))

    def test_set_interface_bad(self):
        '''Test set_interface() - bad'''
        r = self.rules["any"]
        interface = "eth0"
        for if_type in ["ina", "ot"]:
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   r.set_interface,
                                                   if_type,
                                                   interface)

        for if_type in ["in", "out"]:
            for interface in ["\tfoo", "<bad", "also/bad", "eth0:0", "!eth0",
                              "", ".", "..", "$foo", "`uname`", "a" * 16]:
                tests.unit.support.check_for_exception(self,
                                                       ufw.common.UFWError,
                                                       r.set_interface,
                                                       if_type,
                                                       interface)

    def test_set_position(self):
        '''Test set_position()'''
        r = self.rules["any"]
        r.set_position(2)
        self.assertEquals(2, r.position)

    def test_set_position_bad(self):
        '''Test set_position() - bad'''
        r = self.rules["any"]
        tests.unit.support.check_for_exception(self,
                                               ufw.common.UFWError,
                                               r.set_position,
                                               'a')

    def test_set_logtype(self):
        '''Test set_logtype()'''
        r = self.rules["any"]
        for logtype in ["", "log", "log-all"]:
            r.set_logtype(logtype)
            self.assertEquals(logtype, r.logtype, "%s != %s" %
                              (logtype, r.logtype))

    def test_set_logtype_bad(self):
        '''Test set_logtype() - bad'''
        r = self.rules["any"]
        for logtype in ["a", "loga", "d"]:
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   r.set_logtype,
                                                   logtype)

    def test_set_direction(self):
        '''Test set_direction()'''
        r = self.rules["any"]
        for direction in ["in", "out"]:
            r.set_direction(direction)
            self.assertEquals(direction, r.direction, "%s != %s" %
                              (direction, r.direction))

    def test_set_direction_bad(self):
        '''Test set_direction() - bad'''
        r = self.rules["any"]
        for direction in ["", "ina", "outta"]:
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   r.set_direction,
                                                   direction)

    def test_normalize(self):
        '''Test normalize()'''
        # Test the pre-canned rules above-- none of them are normalized, so
        # UFWRule.match() should always be 0
        keys = list(self.rules.keys())
        keys.sort()
        for rule in keys:
            r = self.rules[rule].dup_rule()
            r.normalize()
            self.assertEquals(ufw.common.UFWRule.match(self.rules[rule], r), 0,
                            "'%s' != '%s'" % (self.rules[rule], r))

        # Bad rules
        bad = ufw.common.UFWRule("allow", "any")
        bad.src = "1000.0.0.1"
        tests.unit.support.check_for_exception(self,
                                               ufw.common.UFWError,
                                               bad.normalize)
        bad = None
        bad = ufw.common.UFWRule("allow", "any")
        bad.dst = "1000.0.0.1"
        tests.unit.support.check_for_exception(self,
                                               ufw.common.UFWError,
                                               bad.normalize)

        # Normalized rules
        data = [
                 (False, '192.168.0.1', '192.168.0.1'),
                 (False, '192.168.0.1/31', '192.168.0.0/31'),
                 (False, '192.168.0.1/255.255.255.0', '192.168.0.0/24'),
                 (True, '::1', '::1'),
                 (True, 'ff80:123:4567:89ab:cdef:123:4567:89ab/112',
                        'ff80:123:4567:89ab:cdef:123:4567:89ab/112')
                ]
        for (v6, addr, expected) in data:
            rule = ufw.common.UFWRule("allow", "any", dst=addr)
            rule.set_v6(v6)
            rule.normalize()
            self.assertEquals(expected, rule.dst,
                              "'%s' != '%s'" % (expected, rule.dst))
            self.assertEquals(addr != expected, rule.updated,
                              "'%s' not updated" % addr)

            rule = ufw.common.UFWRule("allow", "any", src=addr)
            rule.set_v6(v6)
            rule.normalize()
            self.assertEquals(expected, rule.src,
                              "'%s' != '%s'" % (expected, rule.src))
            self.assertEquals(addr != expected, rule.updated,
                              "'%s' not updated" % addr)

    def test_match(self):
        '''Test match()'''
        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.match(x, y), 0)

        for action in ['reject', 'deny', 'limit']:
            y = self.rules["full-any"].dup_rule()
            y.set_action(action)
            self.assertEquals(ufw.common.UFWRule.match(x, y), -1)

        for logtype in ['log', 'log-all']:
            y = self.rules["full-any"].dup_rule()
            y.set_logtype(logtype)
            self.assertEquals(ufw.common.UFWRule.match(x, y), -1)

        for comment in ['comment1', 'comment2']:
            y = self.rules["full-any"].dup_rule()
            y.set_comment(comment)
            self.assertEquals(ufw.common.UFWRule.match(x, y), -2)

        y = self.rules["full-any"].dup_rule()
        y.set_port("456", loc="dst")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.set_port("456", loc="src")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.set_protocol("tcp")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.set_src("192.168.0.1")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.set_dst("192.168.0.1")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.set_dst("fe80::1")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = ufw.common.UFWRule("allow", "tcp", dst="fe80::1")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.sapp = "OpenSSH"
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.dapp = "OpenSSH"
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        y = self.rules["full-any"].dup_rule()
        y.set_interface("in", "eth0")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        x = ufw.common.UFWRule("allow", "tcp", direction="out")
        y = x.dup_rule()
        y.set_interface("out", "eth0")
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        x = self.rules["any"].dup_rule()
        y = self.rules["any"].dup_rule()
        y.v6 = True
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        x = self.rules["any"].dup_rule()
        y = self.rules["any"].dup_rule()
        y.forward = True
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        y.forward = True
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        x = self.rules["multi-both"].dup_rule()
        y = self.rules["multi-both"].dup_rule()
        y.forward = True
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        x = ufw.common.UFWRule("allow", "tcp", direction="out")
        x.set_interface("out", "eth0")
        y = x.dup_rule()
        y.direction = "in"
        self.assertEquals(ufw.common.UFWRule.match(x, y), 1)

        tests.unit.support.check_for_exception(self, ValueError,
                                               x.match,
                                               None)

    def test_fuzzy_dst_match(self):
        '''Test fuzzy_dst_match()'''
        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 0)
        x.set_protocol("tcp")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), -1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["multi-dport"].dup_rule()
        y = self.rules["multi-dport"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 0)
        y.set_protocol("any")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), -1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["multi-dport"].dup_rule()
        y = self.rules["multi-dport"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 0)
        y.set_protocol("any")
        y.set_port("%s,8181" % y.dport, "dst")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["any"].dup_rule()
        x.set_port("80")
        x.set_protocol("tcp")
        y = self.rules["multi-dport"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), -1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["any"].dup_rule()
        x.set_port("8081")
        x.set_protocol("tcp")
        y = self.rules["multi-dport"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), -1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["any"].dup_rule()
        x.set_port("8079")
        x.set_protocol("tcp")
        y = self.rules["multi-dport"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 0)
        y.set_direction("out")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)

        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        y.set_dst("10.0.0.3")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        y.set_dst("11.0.0.0/8")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["full-any"].dup_rule()
        y = self.rules["full-any"].dup_rule()
        y.set_interface("in", "eth0")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), -1)

        x = self.rules["full-any"].dup_rule()
        x.set_interface("in", "eth0")
        y = x.dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 0)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 0)

        x = self.rules["full-any"].dup_rule()
        x.set_interface("in", "eth0")
        y = x.dup_rule()
        y.set_interface("in", "eth1")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["full-any"].dup_rule()
        x.set_interface("in", "lo")
        y = x.dup_rule()
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 0)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 0)

        x = self.rules["full-any"].dup_rule()
        x.set_interface("in", "lo")
        y = x.dup_rule()
        y.set_dst("11.0.0.0/8")
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["any"].dup_rule()
        y = x.dup_rule()
        y.set_v6(True)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        x = self.rules["any"].dup_rule()
        y = x.dup_rule()
        y.forward = True
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(x, y), 1)
        self.assertEquals(ufw.common.UFWRule.fuzzy_dst_match(y, x), 1)

        tests.unit.support.check_for_exception(self, ValueError,
                                               x.fuzzy_dst_match,
                                               None)

    def test__is_anywhere(self):
        '''Test _is_anywhere()'''
        r = self.rules['any']
        self.assertTrue(r._is_anywhere("::/0"))
        self.assertTrue(r._is_anywhere("0.0.0.0/0"))
        self.assertFalse(r._is_anywhere("::1"))
        self.assertFalse(r._is_anywhere("fe80::1/16"))
        self.assertFalse(r._is_anywhere("127.0.0.1"))
        self.assertFalse(r._is_anywhere("127.0.0.1/32"))

    def test_get_app_tuple(self):
        '''Test get_app_tuple()'''
        r = self.rules['dapp'].dup_rule()
        t = r.get_app_tuple().split()
        self.assertEquals(self.rules['dapp'].dapp, t[0])
        self.assertEquals(self.rules['dapp'].dst, t[1])
        self.assertEquals("any", t[2])
        self.assertEquals("0.0.0.0/0", t[3])
        r.set_interface("in", "eth0")
        t = r.get_app_tuple().split()
        self.assertEquals(self.rules['dapp'].dapp, t[0])
        self.assertEquals(self.rules['dapp'].dst, t[1])
        self.assertEquals("any", t[2])
        self.assertEquals("0.0.0.0/0", t[3])
        self.assertEquals("in_eth0", t[4])

        r = self.rules['sapp'].dup_rule()
        t = r.get_app_tuple().split()
        self.assertEquals("any", t[0])
        self.assertEquals("0.0.0.0/0", t[1])
        self.assertEquals(self.rules['sapp'].sapp, t[2])
        self.assertEquals(self.rules['sapp'].src, t[3])
        r.set_interface("out", "eth0")
        t = r.get_app_tuple().split()
        self.assertEquals("any", t[0])
        self.assertEquals("0.0.0.0/0", t[1])
        self.assertEquals(self.rules['sapp'].sapp, t[2])
        self.assertEquals(self.rules['sapp'].src, t[3])
        self.assertEquals("out_eth0", t[4])

        # also test with '_' in the name (LP: #1098472)
        r = self.rules['sapp'].dup_rule()
        t = r.get_app_tuple().split()
        self.assertEquals("any", t[0])
        self.assertEquals("0.0.0.0/0", t[1])
        self.assertEquals(self.rules['sapp'].sapp, t[2])
        self.assertEquals(self.rules['sapp'].src, t[3])
        r.set_interface("out", "br_lan")
        t = r.get_app_tuple().split()
        self.assertEquals("any", t[0])
        self.assertEquals("0.0.0.0/0", t[1])
        self.assertEquals(self.rules['sapp'].sapp, t[2])
        self.assertEquals(self.rules['sapp'].src, t[3])
        self.assertEquals("out_br_lan", t[4])


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            CommonTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

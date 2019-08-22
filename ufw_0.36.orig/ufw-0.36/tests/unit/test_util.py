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

import unittest
import tests.unit.support
import ufw.util

import os
import re
import socket

try: # python 2
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import sys
import tempfile


class UtilTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = None

    def tearDown(self):
        if self.tmpdir and os.path.isdir(self.tmpdir):
            tests.unit.support.recursive_rm(self.tmpdir)

    def test_get_services_proto(self):
        '''Test get_services_proto()'''
        # 'any'
        # socket.getservbyname("echo") succeeds
        # socket.getservbyname("echo", "tcp") succeeds
        # socket.getservbyname("echo", "udp") succeeds
        res = ufw.util.get_services_proto("echo")
        self.assertTrue(res == "any", res)

        # 'tcp'
        # socket.getservbyname("tcpmux") succeeds
        # socket.getservbyname("tcpmux", "tcp") succeeds
        # socket.getservbyname("tcpmux", "udp") fails
        res = ufw.util.get_services_proto("tcpmux")
        self.assertTrue(res == "tcp", res)

        # 'udp'
        # socket.getservbyname("fsp") succeeds
        # socket.getservbyname("fsp", "tcp") fails
        # socket.getservbyname("fsp", "udp") succeeds
        res = ufw.util.get_services_proto("fsp")
        self.assertTrue(res == "udp", res)

        # not found
        # socket.getservbyname("ufw-nonexistent") fails
        # socket.getservbyname("ufw-nonexistent", "tcp") fails
        # socket.getservbyname("ufw-nonexistent", "udp") fails
        tests.unit.support.check_for_exception(self, socket.error, \
                                               ufw.util.get_services_proto, \
                                               "ufw-nonexistent")

    def test_parse_port_proto(self):
        '''Test parse_port_proto()'''
        (s, p) = ufw.util.parse_port_proto("7")
        self.assertTrue(s == "7", s)
        self.assertTrue(p == "any", p)

        (s, p) = ufw.util.parse_port_proto("7/tcp")
        self.assertTrue(s == "7", s)
        self.assertTrue(p == "tcp", p)

        (s, p) = ufw.util.parse_port_proto("7/udp")
        self.assertTrue(s == "7", s)
        self.assertTrue(p == "udp", p)

        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.parse_port_proto,
                                               '7/tcp/udp')

    def test_valid_address6(self):
        '''Test valid_address6()'''
        prev = socket.has_ipv6
        socket.has_ipv6 = False
        self.assertFalse(ufw.util.valid_address6('::1'))
        print("(IPv6 support warning is intentional)")
        socket.has_ipv6 = prev

        if not socket.has_ipv6:
            return tests.unit.support.skipped(self, "ipv6 not enabled")

        bad = [
                ':::1',
                'fe80::-1',
                '000000000000000000000000000000000000000000000000001',
                '2001:db8:::/32',
                '2001:db8::/129',
                '2001:gb8::/32',
                '2001:db8:3:4:5:6:7:8:9',
                'foo',
                'xxx:xxx:xxx:xx:xxx:xxx:xxx:xxx',
                'g001:db8:3:4:5:6:7:8',
                '2001:gb8:3:4:5:6:7:8',
                '2001:db8:g:4:5:6:7:8',
                '2001:db8:3:g:5:6:7:8',
                '2001:db8:3:4:g:6:7:8',
                '2001:db8:3:4:5:g:7:8',
                '2001:db8:3:4:5:6:g:8',
                '2001:db8:3:4:5:6:7:g',
                '2001:0db8:0000:0000:0000:0000:0000:0000/129',
                '2001:0db8:0000:0000:0000:0000:0000:00000/128',
                '2001:0db8:0000:0000:0000:0000:0000:00000/12a',
                '::1/128/128',
              ]

        for b in bad:
            self.assertFalse(ufw.util.valid_address6(b), b)

        good = [
                '2001:db8::/32',
                '2001:db8:3:4:5:6:7:8',
                '2001:db8:85a3:8d3:1319:8a2e:370:734',
                '::1',
                '::1/0',
                '::1/32',
                '::1/128',
               ]

        for g in good:
            self.assertTrue(ufw.util.valid_address6(g), g)

    def test_valid_address4(self):
        '''Test valid_address4()'''
        bad = [
                '192.168.0.-1',
                '192.168.0.1/32/32',
                '192.168.256.1',
                '192.s55.0.1',
                '.168.0.1',
                '2001:db8::/32',
                '2001:db8:3:4:5:6:7:8',
                '2001:db8:85a3:8d3:1319:8a2e:370:734',
              ]

        for b in bad:
            self.assertFalse(ufw.util.valid_address4(b), b)

        good = [
                '192.168.0.0',
                '192.168.0.1',
                '192.168.0.254',
                '192.168.0.255',
                '192.168.0.128',
                '192.168.1.128',
                '192.168.254.128',
                '192.168.255.128',
                '192.0.128.128',
                '192.1.128.128',
                '192.254.128.128',
                '192.255.128.128',
                '0.128.128.128',
                '1.128.128.128',
                '254.128.128.128',
                '255.128.128.128',
               ]

        for g in good:
            self.assertTrue(ufw.util.valid_address4(g), g)

    def test_valid_netmask(self):
        '''Test valid_netmask()'''
        # v4
        bad = [
               'a',
               '-1',
               '33',
               '255.255.255.255.0',
               '255.255.255.256',
              ]

        for b in bad:
            self.assertFalse(ufw.util.valid_netmask(b, v6=False), b)

        good = [
                '0',
                '1',
                '16',
                '31',
                '32',
                '255.255.255.0',
                '255.255.128.0',
                '255.64.255.0',
                '32.255.255.0',
               ]

        for g in good:
            self.assertTrue(ufw.util.valid_netmask(g, v6=False), g)

        # v6
        bad = [
               '129',
               '12a',
               'a',
               '-1',
              ]

        for b in bad:
            self.assertFalse(ufw.util.valid_netmask(b, v6=True), b)

        good = [
                '0',
                '1',
                '31',
                '32',
                '33',
                '127',
                '128',
               ]

        for g in good:
            self.assertTrue(ufw.util.valid_netmask(g, v6=True), g)

    def test_valid_address(self):
        '''Test valid_address()'''
        # BAD ADDRESSES
        for v in ['4', 'any']:
            for b in ['16a', '33', '-1']:
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.1/%s" % b, v))

            for b in ['256', 's55', '-1']:
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.%s" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.%s.1" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "192.%s.0.1" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "%s.168.0.1" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "%s.%s.%s.%s" % (b, b, b, b), v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.1/255.255.255.%s" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.1/255.255.%s.255" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.1/255.%s.255.255" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.1/%s.255.255.255" % b, v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.1/%s.%s.%s.%s" % (b, b, b, b), v))
                self.assertFalse(ufw.util.valid_address(
                    "%s.168.0.1/255.255.255.%s" % (b, b), v))
                self.assertFalse(ufw.util.valid_address(
                    "192.%s.0.1/255.255.%s.255" % (b, b), v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.%s.1/255.%s.255.255" % (b, b), v))
                self.assertFalse(ufw.util.valid_address(
                    "192.168.0.%s/%s.255.255.255" % (b, b), v))
                self.assertFalse(ufw.util.valid_address(
                    "%s.%s.%s.%s/%s.%s.%s.%s" % (b, b, b, b, b, b, b, b), v))

        for b in ['129', 's55', '-1']:
            self.assertFalse(ufw.util.valid_address("::1/%s" % b, "6"))

        for b in [':::1', 'fe80::-1', '.168.0.1']:
            self.assertFalse(ufw.util.valid_address(b, "any"), b)
            self.assertFalse(ufw.util.valid_address(b, "4"), b)
            self.assertFalse(ufw.util.valid_address(b, "6"), b)
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.valid_address,
                                               '::1', "7")

        # VALID ADDRESSES
        for v in ['4', 'any']:
            self.assertTrue(ufw.util.valid_address("0.0.0.0", v))
            self.assertTrue(ufw.util.valid_address("0.0.0.0/0", v))
            self.assertTrue(ufw.util.valid_address("0.0.0.0/0.0.0.0", v))
            self.assertTrue(ufw.util.valid_address("10.0.0.1", v))
            self.assertTrue(ufw.util.valid_address("10.0.0.1/32", v))
            self.assertTrue(ufw.util.valid_address("10.0.0.1/255.255.255.255",
                                                   v))
            for i in range(0, 33):
                self.assertTrue(ufw.util.valid_address(
                    "192.168.0.1/%s" % i, v))
            for i in range(0, 256):
                self.assertTrue(ufw.util.valid_address(
                    "192.168.0.1/255.255.255.%s" % i, v))
                self.assertTrue(ufw.util.valid_address(
                    "192.168.0.1/255.255.%s.255" % i, v))
                self.assertTrue(ufw.util.valid_address(
                    "192.168.0.1/255.%s.255.255" % i, v))
                self.assertTrue(ufw.util.valid_address(
                    "192.168.0.1/%s.255.255.255" % i, v))
                self.assertTrue(ufw.util.valid_address(
                    "192.168.0.1/%s.%s.%s.%s" % (i, i, i, i), v))

        for i in range(0, 129):
            self.assertTrue(ufw.util.valid_address("::1/%s" % i, "6"))

        good = [
                '192.168.128.128/255.255.255.129',
                '192.168.0.1',
                '192.168.0.254',
                '192.168.0.255',
                '2001:db8::/32',
                '2001:db8:3:4:5:6:7:8',
                '2001:db8:85a3:8d3:1319:8a2e:370:734',
                '::1',
               ]

        for g in good:
            self.assertTrue(ufw.util.valid_address(g, "any"), g)
            if ':' in g:
                self.assertTrue(ufw.util.valid_address(g, "6"), g)
            else:
                self.assertTrue(ufw.util.valid_address(g, "4"), g)

    def _run_normalize_address(self, data):
        '''Run ufw.util.normalize_address() on data. Data should be in form
           of:
           data = [(v6, ip, expected_ip), (v6, ip2, expected_ip2)]
        '''
        error_str = ""
        for (v6, ip, expected) in data:
            res = ufw.util.normalize_address(ip, v6)[0]
            if expected != res:
                error_str += "'%s' != '%s' (v6=%s)\n" % (res, expected, v6)
        return error_str

    def test_normalize_address_host_netmask(self):
        '''Test normalize_address() with host_netmask'''
        data = [
                (False, '192.168.0.1', '192.168.0.1'),
                (False, '192.168.0.1/32', '192.168.0.1'),
                (False, '192.168.0.1/255.255.255.255', '192.168.0.1'),
                (True, '::1', '::1'),
                (True, '::1/128', '::1'),
               ]

        error_str = self._run_normalize_address(data)
        self.assertEquals(error_str, "", error_str)

    def test_normalize_address_netmask_to_cidr(self):
        '''Test normalize_address() with netmask_to_cidr'''
        data = [
                 (False, '192.168.0.1/255.255.255.255', '192.168.0.1'),
                 (False, '192.168.0.0/255.255.255.254', '192.168.0.0/31'),
                 (False, '192.168.0.0/255.255.255.252', '192.168.0.0/30'),
                 (False, '192.168.0.0/255.255.255.248', '192.168.0.0/29'),
                 (False, '192.168.0.0/255.255.255.240', '192.168.0.0/28'),
                 (False, '192.168.0.0/255.255.255.224', '192.168.0.0/27'),
                 (False, '192.168.0.0/255.255.255.192', '192.168.0.0/26'),
                 (False, '192.168.0.0/255.255.255.128', '192.168.0.0/25'),
                 (False, '192.168.0.0/255.255.255.0', '192.168.0.0/24'),
                 (False, '192.168.0.0/255.255.254.0', '192.168.0.0/23'),
                 (False, '192.168.0.0/255.255.252.0', '192.168.0.0/22'),
                 (False, '192.168.0.0/255.255.248.0', '192.168.0.0/21'),
                 (False, '192.168.0.0/255.255.240.0', '192.168.0.0/20'),
                 (False, '192.168.0.0/255.255.224.0', '192.168.0.0/19'),
                 (False, '192.168.0.0/255.255.192.0', '192.168.0.0/18'),
                 (False, '192.168.0.0/255.255.128.0', '192.168.0.0/17'),
                 (False, '192.168.0.0/255.255.0.0', '192.168.0.0/16'),
                 (False, '192.168.0.0/255.254.0.0', '192.168.0.0/15'),
                 (False, '192.168.0.0/255.252.0.0', '192.168.0.0/14'),
                 (False, '192.168.0.0/255.248.0.0', '192.168.0.0/13'),
                 (False, '192.168.0.0/255.240.0.0', '192.160.0.0/12'),
                 (False, '192.168.0.0/255.224.0.0', '192.160.0.0/11'),
                 (False, '192.168.0.0/255.192.0.0', '192.128.0.0/10'),
                 (False, '192.168.0.0/255.128.0.0', '192.128.0.0/9'),
                 (False, '192.168.0.0/255.0.0.0', '192.0.0.0/8'),
                 (False, '192.168.0.0/254.0.0.0', '192.0.0.0/7'),
                 (False, '192.168.0.0/252.0.0.0', '192.0.0.0/6'),
                 (False, '192.168.0.0/248.0.0.0', '192.0.0.0/5'),
                 (False, '192.168.0.0/240.0.0.0', '192.0.0.0/4'),
                 (False, '192.168.0.0/224.0.0.0', '192.0.0.0/3'),
                 (False, '192.168.0.0/192.0.0.0', '192.0.0.0/2'),
                 (False, '192.168.0.0/128.0.0.0', '128.0.0.0/1'),
                ]

        error_str = self._run_normalize_address(data)
        self.assertEquals(error_str, "", error_str)

    def test_normalize_address_ipv6_cidr(self):
        '''Test normalize_address() with ipv6_cidr'''
        data = []
        for cidr in range(0, 128):
            data.append((True, '::1/%d' % cidr, '::1/%d' % cidr))
        error_str = self._run_normalize_address(data)
        self.assertEquals(error_str, "", error_str)

    def test_normalize_address_valid_netmask_to_non_cidr(self):
        '''Test normalize_address() with valid_netmask_to_non_cidr'''
        data = []

        cidrs = [252, 248, 240, 224, 192, 128]
        for i in range(1, 254):
            if i in cidrs:
                continue
            data.append((False, '192.168.0.0/255.255.255.%d' % i,
                                '192.168.0.0/255.255.255.%d' % i))
            if i < 8:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.0.0.0/255.%d.0.0' % i))
            elif i < 16:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.8.0.0/255.%d.0.0' % i))
            elif i < 24:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.0.0.0/255.%d.0.0' % i))
            elif i < 32:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.8.0.0/255.%d.0.0' % i))
            elif i < 40:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.32.0.0/255.%d.0.0' % i))
            elif i < 48:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.40.0.0/255.%d.0.0' % i))
            elif i < 56:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.32.0.0/255.%d.0.0' % i))
            elif i < 64:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.40.0.0/255.%d.0.0' % i))
            elif i < 72:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.0.0.0/255.%d.0.0' % i))
            elif i < 80:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.8.0.0/255.%d.0.0' % i))
            elif i < 88:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.0.0.0/255.%d.0.0' % i))
            elif i < 96:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.8.0.0/255.%d.0.0' % i))
            elif i < 104:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.32.0.0/255.%d.0.0' % i))
            elif i < 112:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.40.0.0/255.%d.0.0' % i))
            elif i < 120:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.32.0.0/255.%d.0.0' % i))
            elif i < 128:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.40.0.0/255.%d.0.0' % i))
            elif i < 136:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.128.0.0/255.%d.0.0' % i))
            elif i < 144:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.136.0.0/255.%d.0.0' % i))
            elif i < 152:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.128.0.0/255.%d.0.0' % i))
            elif i < 160:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.136.0.0/255.%d.0.0' % i))
            elif i < 168:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.160.0.0/255.%d.0.0' % i))
            elif i < 176:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.168.0.0/255.%d.0.0' % i))
            elif i < 184:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.160.0.0/255.%d.0.0' % i))
            elif i < 192:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.168.0.0/255.%d.0.0' % i))
            elif i < 200:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.128.0.0/255.%d.0.0' % i))
            elif i < 208:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.136.0.0/255.%d.0.0' % i))
            elif i < 216:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.128.0.0/255.%d.0.0' % i))
            elif i < 224:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.136.0.0/255.%d.0.0' % i))
            elif i < 232:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.160.0.0/255.%d.0.0' % i))
            elif i < 240:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.168.0.0/255.%d.0.0' % i))
            elif i < 248:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.160.0.0/255.%d.0.0' % i))
            elif i < 256:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.168.0.0/255.%d.0.0' % i))
            else:
                data.append((False, '192.168.0.0/255.%d.0.0' % i,
                                    '192.168.0.0/255.%d.0.0' % i))

            if i < 64:
                data.append((False, '192.168.0.0/%d.0.0.0' % i,
                                    '0.0.0.0/%d.0.0.0' % i))
            elif i < 128:
                data.append((False, '192.168.0.0/%d.0.0.0' % i,
                                    '64.0.0.0/%d.0.0.0' % i))
            elif i < 192:
                data.append((False, '192.168.0.0/%d.0.0.0' % i,
                                    '128.0.0.0/%d.0.0.0' % i))
            else:
                data.append((False, '192.168.0.0/%d.0.0.0' % i,
                                    '192.0.0.0/%d.0.0.0' % i))

        error_str = self._run_normalize_address(data)
        self.assertEquals(error_str, "", error_str)

    def test_normalize_address_ipv6_short_notation(self):
        '''Test normalize_address() with ipv6_short_notation'''
        data = [
                 (True, 'fe80:0000:0000:0000:0211:aaaa:bbbb:d54c',
                        'fe80::211:aaaa:bbbb:d54c'),
                 (True, '2001:0db8:85a3:08d3:1319:8a2e:0370:734',
                        '2001:db8:85a3:8d3:1319:8a2e:370:734'),
                ]
        error_str = self._run_normalize_address(data)
        self.assertEquals(error_str, "", error_str)

    def test_normalize_address_invalid_netmask(self):
        '''Test normalize_address() with invalid_netmask'''
        data = [
                 (True, '::1/-1', ValueError),
                 (True, '::1/129', ValueError),
                 (True, '::1/3e', ValueError),
                 (False, '192.168.0.1/-1', socket.error),
                 (False, '192.168.0.1/33', ValueError),
                 (False, '192.168.0.1/e1', socket.error),
                ]
        for (v6, ip, expected) in data:
            tests.unit.support.check_for_exception(self, expected, \
                    ufw.util.normalize_address, ip, v6)

    def test_open_file_read(self):
        '''Test open_file_read()'''
        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        tests.unit.support.check_for_exception(self, IOError, \
                    ufw.util.open_file_read, tmp + 'nonexistent')

        f = ufw.util.open_file_read(tmp)
        f.close()

    def test_open_files(self):
        '''Test open_files()'''
        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        tests.unit.support.check_for_exception(self, IOError, \
                    ufw.util.open_files, tmp + 'nonexistent')

        fns = ufw.util.open_files(tmp)
        fns['orig'].close()
        os.close(fns['tmp'])
        os.unlink(fns['tmpname'])

    def test_write_to_file(self):
        '''Test write_to_file()'''
        tests.unit.support.check_for_exception(self, OSError, \
                    ufw.util.write_to_file, None, 'foo')

        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        fns = ufw.util.open_files(tmp)
        ufw.util.write_to_file(fns['tmp'], "")
        ufw.util.write_to_file(fns['tmp'], "test")

        fns['orig'].close()
        os.close(fns['tmp'])
        os.unlink(fns['tmpname'])

        search = "test string"
        ufw.util.msg_output = StringIO()
        ufw.util.write_to_file(sys.stdout.fileno(), search)
        out = ufw.util.msg_output.getvalue()
        if sys.version_info[0] >= 3:
            search = bytes(search, 'ascii')
            out = bytes(out, 'ascii')
        self.assertEquals(out, search)
        ufw.util.msg_output.close()
        ufw.util.msg_output = None

    def test_close_files(self):
        '''Test close_files()'''
        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        fns = ufw.util.open_files(tmp)
        ufw.util.close_files(fns)

        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        fns = ufw.util.open_files(tmp)
        ufw.util.close_files(fns, update=False)

        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        fns = ufw.util.open_files(tmp)
        os.unlink(fns['origname'])
        tests.unit.support.check_for_exception(self, OSError,
                                               ufw.util.close_files,
                                               fns, True)

        self.tmpdir = tempfile.mkdtemp()
        tmp = os.path.join(self.tmpdir, "foo")
        f = open(tmp, 'w')
        f.close()

        fns = ufw.util.open_files(tmp)
        os.unlink(fns['tmpname'])
        tests.unit.support.check_for_exception(self, OSError,
                                               ufw.util.close_files,
                                               fns, False)

    def test_cmd(self):
        '''Test cmd()'''
        (rc, report) = ufw.util.cmd(['ls', '/'])
        self.assertEquals(rc, 0, "Unexpected return code: %d" % rc)
        self.assertTrue('etc' in report, "Could not find 'etc'in:\n%s" % \
                        report)
        (rc, report) = ufw.util.cmd(['./nonexistent-command'])
        self.assertEquals(rc, 127, "Unexpected return code: %d" % rc)

    def test_cmd_pipe(self):
        '''Test cmd_pipe()'''
        (rc, report) = ufw.util.cmd_pipe(['ls', '/'], ['grep', '-q', 'etc'])
        self.assertEquals(rc, 0, "Unexpected return code: %d" % rc)
        (rc, report) = ufw.util.cmd_pipe(['./nonexistent-command'],
                                         ['grep', '-q', 'etc'])
        self.assertEquals(rc, 127, "Unexpected return code: %d" % rc)

    def test_error(self):
        '''Test error()'''
        ufw.util.error("test error()", do_exit=False)
        print("('ERROR: test error()' output is intentional)")

    def test_warn(self):
        '''Test warn()'''
        ufw.util.warn("test warn()")
        print("('WARN: test warn()' output is intentional)")

    def test_msg(self):
        '''Test msg()'''
        ufw.util.msg("test msg()")
        print("('test msg()' output is intentional)")

        ufw.util.msg("test msg()", newline=False)
        print("\n('test msg()' output is intentional)")

        search = "test string"
        ufw.util.msg_output = StringIO()
        ufw.util.msg(search, newline=False)
        out = ufw.util.msg_output.getvalue()
        if sys.version_info[0] >= 3:
            search = bytes(search, 'ascii')
            out = bytes(out, 'ascii')
        self.assertEquals(out, search)
        ufw.util.msg_output.close()
        ufw.util.msg_output = None

    def test_debug(self):
        '''Test debug()'''
        prev = ufw.util.DEBUGGING
        ufw.util.DEBUGGING = True
        ufw.util.debug("test debug()")
        print("('DEBUG: test debug()' output is intentional)")
        ufw.util.DEBUGGING = prev

    def test_word_wrap(self):
        '''Test word_wrap()'''
        s = ufw.util.word_wrap("foo\nbar baz", 3)
        expected = "foo\nbar\nbaz"
        self.assertEquals(s, expected, "'%s' != '%s'" % (s, expected))

    def test_wrap_text(self):
        '''Test wrap_text()'''
        t = '''
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAA
'''
        expected = '''
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAA
'''
        s = ufw.util.wrap_text(t)
        self.assertEquals(s, expected, "'%s' != '%s'" % (s, expected))

    def test_human_sort(self):
        '''Test human_sort()'''
        s = '80,a222,a32,a2,b1,443,telnet,3,ZZZ,http'
        expected = '3,80,443,a2,a32,a222,b1,http,telnet,ZZZ'

        tmp = s.split(',')
        ufw.util.human_sort(tmp)
        res = ",".join(tmp)
        self.assertEquals(str(res), expected)

    def test_get_ppid(self):
        '''Test get_ppid()'''
        ufw.util.get_ppid()
        ppid = ufw.util.get_ppid(1)
        self.assertEquals(ppid, 0, "%d' != '0'" % ppid)

        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.get_ppid, 'a')
        tests.unit.support.check_for_exception(self, IOError, \
                                               ufw.util.get_ppid, 0)

    def test_under_ssh(self):
        '''Test under_ssh()'''
        # this test could be running under ssh, so can't do anything more
        ufw.util.under_ssh()

        self.assertFalse(ufw.util.under_ssh(1))
        self.assertFalse(ufw.util.under_ssh(0))
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.under_ssh, 'a')

    def test__valid_cidr_netmask(self):
        '''Test _valid_cidr_netmask()'''
        self.assertFalse(ufw.util._valid_cidr_netmask('a', False))
        self.assertFalse(ufw.util._valid_cidr_netmask('a', True))
        self.assertFalse(ufw.util._valid_cidr_netmask('-1', False))
        self.assertFalse(ufw.util._valid_cidr_netmask('-1', True))
        self.assertFalse(ufw.util._valid_cidr_netmask('33', False))
        self.assertFalse(ufw.util._valid_cidr_netmask('129', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('0', False))
        self.assertTrue(ufw.util._valid_cidr_netmask('15', False))
        self.assertTrue(ufw.util._valid_cidr_netmask('16', False))
        self.assertTrue(ufw.util._valid_cidr_netmask('17', False))
        self.assertTrue(ufw.util._valid_cidr_netmask('32', False))
        self.assertTrue(ufw.util._valid_cidr_netmask('0', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('31', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('32', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('33', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('63', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('64', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('65', True))
        self.assertTrue(ufw.util._valid_cidr_netmask('128', True))

    def test__valid_dotted_quads(self):
        '''Test _valid_dotted_quads()'''
        # Fill in gaps that can't be tested via other tests
        self.assertFalse(ufw.util._valid_dotted_quads('255.255.255.255', True))
        self.assertFalse(ufw.util._valid_dotted_quads('a.255.255.255', False))
        self.assertFalse(ufw.util._valid_dotted_quads('255.255.255', False))
        self.assertFalse(ufw.util._valid_dotted_quads('255.255.255', False))
        self.assertFalse(ufw.util._valid_dotted_quads('255.255.255.256', False))
        self.assertTrue(ufw.util._valid_dotted_quads('255.255.255.255', False))

    def test__dotted_netmask_to_cidr(self):
        '''Test _dotted_netmask_to_cidr()'''
        # Fill in gaps that can't be tested via other tests
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util._dotted_netmask_to_cidr,
                                               '255.255.255.255', True)
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util._dotted_netmask_to_cidr,
                                               '255.255.255.256', False)

    def test__cidr_to_dotted_netmask(self):
        '''Test _cidr_to_dotted_netmask()'''
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util._cidr_to_dotted_netmask,
                                               '32', True)
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util._cidr_to_dotted_netmask,
                                               '33', False)

    def test_cidr_to_dotted_to_cidr(self):
        '''Test _cidr_to_dotted_netmask() and _dotted_netmask_to_cidr()'''
        for m in range(0, 33):
            cidr = str(m)
            dotted = ufw.util._cidr_to_dotted_netmask(cidr, False)
            reverse = ufw.util._dotted_netmask_to_cidr(dotted, False)
            self.assertEquals(cidr, reverse,
                            "cidr=%s, dotted=%s, reverse=%s" % (cidr,
                                                                dotted,
                                                                reverse))

    def test__address4_to_network(self):
        '''Test _address4_to_network()'''
        n = ufw.util._address4_to_network("192.168.1.1/16")
        self.assertEquals(n, "192.168.0.0/16")
        n = "192.168.1.1"
        self.assertEquals(n, ufw.util._address4_to_network(n))
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util._address4_to_network,
                                               '192.168.1.1/16/16')

    def test__address6_to_network(self):
        '''Test _address6_to_network()'''
        n = ufw.util._address6_to_network("ff81::1/15")
        self.assertEquals(n, "ff80::/15")
        n = "ff80::1"
        self.assertEquals(n, ufw.util._address6_to_network(n))
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util._address6_to_network,
                                               'ff80::1/16/16')

    def test_in_network(self):
        '''Test in_network()'''
        for i in range(0, 33):
            self.assertTrue(ufw.util.in_network("10.2.0.1",
                                                "10.2.0.1/%d" % i,
                                                False))
        self.assertFalse(ufw.util.in_network("10.2.0.1",
                                             "10.2.0.0/32",
                                             False))
        self.assertTrue(ufw.util.in_network("11.0.0.1",
                                            "10.2.0.1/7",
                                            False))
        self.assertFalse(ufw.util.in_network("11.0.0.1",
                                             "10.2.0.1/8",
                                             False))
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.in_network,
                                                   "10.2.0.1",
                                                   "10.2.0.1/33",
                                                   False)
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.in_network,
                                                   "10.2.0.1234",
                                                   "10.2.0.1/24",
                                                   False)
        self.assertTrue(ufw.util.in_network("10.2.0.1",
                                            "0.0.0.0/0",
                                            False))
        self.assertTrue(ufw.util.in_network("10.2.0.1/26",
                                            "10.2.0.1/24",
                                            False))
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.in_network,
                                               "10.2.0.1/16/16",
                                               "10.2.0.1/24",
                                               False)
        self.assertTrue(ufw.util.in_network("0.0.0.0",
                                            "10.2.0.1/24",
                                            False))

        for i in range(0, 129):
            self.assertTrue(ufw.util.in_network("ff80::1",
                                                "ff80::1/%d" % i,
                                                True))
        self.assertFalse(ufw.util.in_network("ff80::1",
                                             "ff80::0/128",
                                             True))
        self.assertTrue(ufw.util.in_network("ff81::1",
                                            "ff80::1/15",
                                            True))
        self.assertFalse(ufw.util.in_network("ff81::1",
                                             "ff80::1/16",
                                             True))
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.in_network,
                                               "ff80::1",
                                               "ff80::1/129",
                                               True)
        tests.unit.support.check_for_exception(self, ValueError, \
                                               ufw.util.in_network,
                                               "gf80::1",
                                               "ff80::1/64",
                                               True)
        self.assertTrue(ufw.util.in_network("ff80::1",
                                            "::/0",
                                            True))
        self.assertTrue(ufw.util.in_network("::/0",
                                            "ff80::1/64",
                                            True))

    def test_get_iptables_version(self):
        '''Test get_iptables_version()'''
        tests.unit.support.check_for_exception(self, OSError, \
                                               ufw.util.get_iptables_version, \
                                               'iptables-nonexistent')
        v = ufw.util.get_iptables_version()
        self.assertTrue(re.match(r'^[0-9]', v))

    def test_get_netfilter_capabilities(self):
        '''Test get_netfilter_capabilities()'''
        # Verify we are root check
        tests.unit.support.check_for_exception(self, OSError, \
                 ufw.util.get_netfilter_capabilities)

        # use fake iptables to verify other bits of the code
        exe = os.path.join(ufw.common.iptables_dir, "iptables")
        ufw.util.get_netfilter_capabilities(exe=exe, do_checks=False)

        exe = os.path.join(ufw.common.iptables_dir, "ip6tables")
        ufw.util.get_netfilter_capabilities(exe=exe, do_checks=False)

    def test_parse_netstat_output(self):
        '''Test parse_netstat_output()'''
        min_out = 1
        if not tests.unit.support.has_proc_net_output():
            min_out = 0
        s = ufw.util.parse_netstat_output(False)
        self.assertTrue(len(s) >= min_out)
        s = ufw.util.parse_netstat_output(True)
        self.assertTrue(len(s) >= min_out)

    def test_get_ip_from_if(self):
        '''Test get_ip_from_if()'''
        if sys.version_info[0] >= 3:
            return tests.unit.support.skipped(self, "TODO: python3")

        ip = ufw.util.get_ip_from_if("lo", False)
        self.assertTrue(ip.startswith("127"))

        tests.unit.support.check_for_exception(self, IOError, \
                 ufw.util.get_ip_from_if, "nonexistent", False)

        # just run through the code, we may not have an IPv6 address
        try:
            ufw.util.get_ip_from_if("lo", True)
        except IOError:
            pass

    def test_get_if_from_ip(self):
        '''Test get_if_from_ip()'''
        if sys.version_info[0] >= 3:
            return tests.unit.support.skipped(self, "TODO: python3")

        iface = ufw.util.get_if_from_ip("127.0.0.1")
        self.assertTrue(iface.startswith("lo"))
        self.assertFalse(ufw.util.get_if_from_ip("127.255.255.255"))
        tests.unit.support.check_for_exception(self, IOError, \
                 ufw.util.get_if_from_ip, "nonexistent")

        # just run through the code, we may not have an IPv6 address
        try:
            ufw.util.get_if_from_ip("::1")
        except IOError:
            pass

    def test__get_proc_inodes(self):
        '''Test _get_proc_inodes()'''
        inodes = ufw.util._get_proc_inodes()
        self.assertTrue(len(inodes) > 0)

    def test__read_proc_net_protocol(self):
        '''Test _read_proc_net_protocol()'''
        res = ufw.util._read_proc_net_protocol("tcp")
        # self.assertTrue(len(res) > 0)
        if len(res) <= 0:
            print("(TODO: fake-netstat) could not find tcp entries")

        res = ufw.util._read_proc_net_protocol("udp")
        # self.assertTrue(len(res) > 0)
        if len(res) <= 0:
            print("(TODO: fake-netstat) could not find udp entries")

    # covered by other tests
    #def test_convert_proc_address(self):
    #    '''Test convert_proc_address()'''

    def test_get_netstat_output(self):
        '''Test get_netstat_output()'''
        s = ufw.util.get_netstat_output(True)
        # self.assertTrue("tcp" in s)
        # self.assertTrue("udp" in s)
        if "tcp" not in s:
            print("(TODO: fake-netstat) could not find tcp in:\n%s" % s)
        if "udp" not in s:
            print("(TODO: fake-netstat) could not find udp in:\n%s" % s)

        s = ufw.util.get_netstat_output(False)
        # self.assertTrue("tcp" in s)
        # self.assertTrue("udp" in s)
        if "tcp" not in s:
            print("(TODO: fake-netstat) could not find tcp in:\n%s" % s)
        if "udp" not in s:
            print("(TODO: fake-netstat) could not find udp in:\n%s" % s)

    def test_hex_encode(self):
        '''Test hex_encode() output'''
        s = 'foo👍bar字baz'
        expected = '666f6ff09f918d626172e5ad9762617a'

        result = ufw.util.hex_encode(s)
        self.assertEquals(expected, result)

    def test_hex_decode(self):
        '''Test hex_decode() output'''
        s = '666f6ff09f918d626172e5ad9762617a'
        expected = 'foo👍bar字baz'
        if sys.version_info[0] < 3:
            expected = u'foo👍bar字baz'

        result = ufw.util.hex_decode(s)
        self.assertEquals(expected, result)

    def test_create_lock(self):
        '''Test create_lock()'''
        lock = ufw.util.create_lock(dryrun=True)
        self.assertTrue(lock is None)
        ufw.util.release_lock(lock)

        self.tmpdir = tempfile.mkdtemp()
        fn = os.path.join(self.tmpdir, "lock")
        lock = ufw.util.create_lock(lockfile=fn, dryrun=False)
        self.assertTrue(lock is not None)
        ufw.util.release_lock(lock)


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            UtilTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

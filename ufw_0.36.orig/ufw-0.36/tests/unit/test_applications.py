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

import os
import unittest
import tests.unit.support
import ufw.applications


class ApplicationsTestCase(unittest.TestCase):
    def setUp(self):
        apps = os.path.join(ufw.common.config_dir, "ufw/applications.d")
        self.profiles = ufw.applications.get_profiles(apps)

    def tearDown(self):
        pass

    def test_get_profiles(self):
        '''Test get_profiles()'''
        try:
            ufw.applications.get_profiles("foo")
            self.assertFalse(True)
        except ufw.common.UFWError:
            pass

        self.assertTrue('WWW' in self.profiles.keys(), "Could not find 'WWW'")
        self.assertEquals(self.profiles['WWW']['ports'], "80/tcp")
        self.assertEquals(self.profiles['WWW']['title'], "Web Server")
        self.assertEquals(self.profiles['WWW']['description'], "Web server")

    def test_valid_profile_name(self):
        '''Test valid_profile_name()'''
        self.assertTrue(ufw.applications.valid_profile_name('ABC'))
        self.assertFalse(ufw.applications.valid_profile_name('#ABC'))
        self.assertFalse(ufw.applications.valid_profile_name('all'))
        self.assertFalse(ufw.applications.valid_profile_name('123'))
        self.assertFalse(ufw.applications.valid_profile_name('AB*C'))

    def test_verify_profile(self):
        '''Test verify_profile()'''
        profiles = [{'title': 'test both',
                     'description': 'dns',
                     'ports': '53'},
                    {'title': 'test tcp',
                     'description': 'desc',
                     'ports': '22/tcp'},
                    {'title': 'test udp',
                     'description': 'desc',
                     'ports': '123/udp'},
                    {'title': 'test multi comma',
                     'description': 'desc',
                     'ports': '80,443/tcp'},
                    {'title': 'test multi range',
                     'description': 'desc',
                     'ports': '60000:65000/udp'},
                    {'title': 'test different',
                     'description': 'desc',
                     'ports': '123/udp|80/tcp'},
                    {'title': 'test man page',
                     'description': 'desc',
                     'ports': '12/udp|34|56,78:90/tcp'},
                    ]
        for p in profiles:
            self.assertTrue(ufw.applications.verify_profile('TESTPROFILE', p))

    def test_verify_profile_bad(self):
        '''Test verify_profile() - bad'''
        profiles = [{'description': 'missing title',
                     'ports': '53'},
                    {'title': 'missing description',
                     'ports': '22/tcp'},
                    {'title': 'missing ports',
                     'description': 'desc'},
                    {'title': '',
                     'description': 'empty title',
                     'ports': '80'},
                    {'title': 'empty description',
                     'description': '',
                     'ports': '80'},
                    {'title': 'empty ports',
                     'description': 'desc',
                     'ports': ''},
                    {'title': 'bad missing proto - list',
                     'description': 'desc',
                     'ports': '80,443'},
                    {'title': 'bad missing proto - range',
                     'description': 'desc',
                     'ports': '80:443'},
                    {'title': 'bad range too big',
                     'description': 'desc',
                     'ports': '80:70000/tcp'},
                    {'title': 'bad protocol - ah',
                     'description': 'desc',
                     'ports': '80/ah'},
                    {'title': 'bad protocol - esp',
                     'description': 'desc',
                     'ports': '80/esp'},
                    {'title': 'bad protocol - gre',
                     'description': 'desc',
                     'ports': '80/gre'},
                    {'title': 'bad protocol - igmp',
                     'description': 'desc',
                     'ports': '80/igmp'},
                    {'title': 'bad protocol - ipv6',
                     'description': 'desc',
                     'ports': '80/ipv6'},
                    ]
        for p in profiles:
            print(" %s" % p)
            tests.unit.support.check_for_exception(self,
                                                   ufw.common.UFWError,
                                                   ufw.applications.verify_profile,
                                                   'TESTPROFILE', p)

    def test_get_title(self):
        '''Test get_title()'''
        self.assertEquals(ufw.applications.get_title(self.profiles['WWW']),
                'Web Server')

    def test_get_description(self):
        '''Test get_description()'''
        self.assertEquals(ufw.applications.get_description(self.profiles['WWW']),
                'Web server')

    def test_get_ports(self):
        '''Test get_ports()'''
        expected_ports = ['80/tcp']
        self.assertEquals(ufw.applications.get_ports(self.profiles['WWW']),
                expected_ports)


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            ApplicationsTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

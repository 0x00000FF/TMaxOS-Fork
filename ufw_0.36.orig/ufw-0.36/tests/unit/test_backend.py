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
# NOTE: most of this is tested via test_backend_iptables.py since we have to
#       have a backend defined to test backend.py

import unittest
import tests.unit.support
import ufw.backend
import ufw.backend_iptables
import ufw.common


class BackendTestCase(unittest.TestCase):
    def setUp(self):
        ufw.common.do_checks = False
        # ufw.backend is an interface, so to test it we need to instantiate
        # an object that implements this interface
        self.backend = ufw.backend_iptables.UFWBackendIptables(dryrun=True)

    def tearDown(self):
        pass

    def test_installation_defaults(self):
        '''Test installation defaults'''
        self.assertEquals(self.backend.defaults['default_input_policy'],
                          "drop")
        self.assertEquals(self.backend.defaults['default_forward_policy'],
                          "drop")
        self.assertEquals(self.backend.defaults['default_output_policy'],
                          "accept")
        self.assertEquals(self.backend.defaults['ipt_modules'],
                        'nf_conntrack_ftp nf_nat_ftp nf_conntrack_netbios_ns')
        self.assertEquals(self.backend.defaults['loglevel'], 'low')
        self.assertEquals(self.backend.defaults['manage_builtins'], 'no')
        self.assertEquals(self.backend.defaults['enabled'], 'no')
        self.assertEquals(self.backend.defaults['ipv6'], 'yes')
        self.assertEquals(self.backend.defaults['default_application_policy'],
                          'skip')


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            BackendTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

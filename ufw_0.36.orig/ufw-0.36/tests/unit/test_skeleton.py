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


class SkeletonTestCase(unittest.TestCase):
    def setUp(self):

        pass

    def tearDown(self):
        pass

    def test_example(self):
        '''Test example dummy test'''
        import ufw.common
        try:
            raise ufw.common.UFWError("test")
        except ufw.common.UFWError:
            pass


def test_main(): # used by runner.py
    tests.unit.support.run_unittest(
            SkeletonTestCase
    )


if __name__ == "__main__": # used when standalone
    unittest.main()

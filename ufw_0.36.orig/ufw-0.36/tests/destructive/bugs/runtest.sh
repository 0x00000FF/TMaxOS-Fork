#!/bin/bash

#    Copyright 2008-2012 Canonical Ltd.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

source "$TESTPATH/../testlib.sh"

# Don't display tracebacks
sed -i 's/problem running ufw-init\\n%s" % out)/problem running ufw-init")/' $TESTPATH/lib/python/ufw/backend_iptables.py

echo "These tests are destructive and should only be run in a virtual machine"
echo -n "Continue (y|N)? "
read ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
    echo "Continuing with destructive tests..."
else
    echo "Skipping destructive tests"
    exit 0
fi

trap "mv -f /sbin/iptables.bak /sbin/iptables" EXIT HUP INT QUIT TERM
echo "Bug #262451 (part 2)" >> $TESTTMP/result
do_cmd "0"  disable
do_cmd "0"  status
mv /sbin/iptables /sbin/iptables.bak || true
do_cmd "1"  enable
do_cmd "1"  status
mv /sbin/iptables.bak /sbin/iptables
trap - EXIT HUP INT QUIT TERM

trap "mount -t proc /proc /proc" EXIT HUP INT QUIT TERM
echo "Bug #268084" >> $TESTTMP/result
do_cmd "0"  disable
umount /proc

mount | egrep -q '^(|/)proc '
if [ "$?" == "0" ]; then
    echo "  Skipping (/proc still mounted)" >> $TESTTMP/result
else
    do_cmd "0"  enable
    do_cmd "0"  status
    do_cmd "0"  app update all
    mount -t proc /proc /proc
    do_cmd "0"  disable
    do_cmd "0"  enable
    do_cmd "0"  status
fi
trap - EXIT HUP INT QUIT TERM

# teardown
cleanup

exit 0

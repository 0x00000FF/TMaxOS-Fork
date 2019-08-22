#!/bin/bash

#    Copyright 2014 Canonical Ltd.
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

echo "Man page" >> $TESTTMP/result
do_cmd "0" --dry-run route deny proto udp from 1.2.3.4 to any port 514
do_cmd "0" --dry-run route delete deny proto udp from 1.2.3.4 to any port 514
do_cmd "0" --dry-run route allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
do_cmd "0" --dry-run route delete allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469

echo "SIMPLE" >> $TESTTMP/result
do_cmd "0" --dry-run route allow daytime
do_cmd "0" --dry-run route delete allow daytime
do_cmd "0" --dry-run route allow daytime/tcp
do_cmd "0" --dry-run route delete allow daytime/tcp
do_cmd "0" --dry-run route allow daytime/udp
do_cmd "0" --dry-run route delete allow daytime/udp

echo "Interfaces" >> $TESTTMP/result
in_if="fake0"
out_if="fake1"
do_cmd "0" --dry-run route allow in on $in_if
do_cmd "0" --dry-run route delete allow in on $in_if
do_cmd "0" --dry-run route deny out on $out_if
do_cmd "0" --dry-run route delete deny out on $out_if

echo "TO/FROM" >> $TESTTMP/result
from="192.168.0.1"
to="10.0.0.1"
do_cmd "0" --dry-run route allow from $from
do_cmd "0" --dry-run route delete allow from $from
do_cmd "0" --dry-run route deny to $to
do_cmd "0" --dry-run route delete deny to $to
do_cmd "0" --dry-run route limit to $to from $from
do_cmd "0" --dry-run route delete limit to $to from $from

do_cmd "0" --dry-run route allow in on $in_if from $from
do_cmd "0" --dry-run route delete allow in on $in_if from $from
do_cmd "0" --dry-run route deny out on $out_if to $to
do_cmd "0" --dry-run route delete deny out on $out_if to $to
do_cmd "0" --dry-run route limit in on $in_if out on $out_if from $from to $to
do_cmd "0" --dry-run route delete limit in on $in_if out on $out_if from $from to $to

do_cmd "0" --dry-run route allow from $from port 80
do_cmd "0" --dry-run route delete allow from $from port 80
do_cmd "0" --dry-run route deny to $to port 25
do_cmd "0" --dry-run route delete deny to $to port 25
do_cmd "0" --dry-run route limit in on $in_if out on $out_if from $from port 25 to $to port 25 proto tcp
do_cmd "0" --dry-run route delete limit in on $in_if out on $out_if from $from port 25 to $to port 25 proto tcp

echo "Services" >> $TESTTMP/result
do_cmd "0" --dry-run route allow to any port smtp from any port smtp
do_cmd "0" --dry-run route delete allow to any port smtp from any port smtp
do_cmd "0" --dry-run route allow in on $in_if out on $out_if to any port smtp from any port smtp
do_cmd "0" --dry-run route delete allow in on $in_if out on $out_if to any port smtp from any port smtp

echo "Netmasks" >> $TESTTMP/result
do_cmd "0" --dry-run route reject from 192.168.0.1/32 to 192.168.0.0/16
do_cmd "0" --dry-run route delete reject from 192.168.0.1/32 to 192.168.0.0/16

echo "Multiports:" >> $TESTTMP/result
do_cmd "0" --dry-run route limit 23,21,15:19,13/tcp
do_cmd "0" --dry-run route delete limit 23,21,15:19,13/tcp
do_cmd "0" --dry-run route allow in on $in_if out on $out_if from 192.168.0.1 port 23,21,15:19,13 to 10.0.0.0/8 port 24:26 proto tcp
do_cmd "0" --dry-run route delete allow in on $in_if out on $out_if from 192.168.0.1 port 23,21,15:19,13 to 10.0.0.0/8 port 24:26 proto tcp
do_cmd "0" --dry-run route deny in on $in_if to any port 34,35:39 from any port 24 proto udp
do_cmd "0" --dry-run route delete deny in on $in_if to any port 34,35:39 from any port 24 proto udp

echo "Insert" >> $TESTTMP/result
do_cmd "0" null route allow 13
do_cmd "0" null route allow 23

do_cmd "0" null route insert 1 allow 9999
do_cmd "0" null route insert 1 allow log 9998
do_cmd "0" null route insert 2 reject to 192.168.0.1 from 10.0.0.1
cat $TESTCONFIG/user.rules >> $TESTTMP/result

do_cmd "0" null route delete allow 13
do_cmd "0" null route delete allow 23
do_cmd "0" null route delete allow 9999
do_cmd "0" null route delete allow log 9998
do_cmd "0" null route delete reject to 192.168.0.1 from 10.0.0.1
cat $TESTCONFIG/user.rules >> $TESTTMP/result

echo "ipv6 protocols" >> $TESTTMP/result
do_cmd "0" --dry-run route allow in on $in_if to 10.0.0.1 proto ipv6
do_cmd "0" --dry-run route delete allow in on $in_if to 10.0.0.1 proto ipv6
do_cmd "0" --dry-run route deny out on $out_if to 10.0.0.1 from 10.4.0.0/16 proto ah
do_cmd "0" --dry-run route delete deny out on $out_if to 10.0.0.1 from 10.4.0.0/16 proto ah
do_cmd "0" --dry-run route limit in on $in_if out on $out_if to 10.0.0.1 proto esp
do_cmd "0" --dry-run route delete limit in on $in_if out on $out_if to 10.0.0.1 proto esp

exit 0

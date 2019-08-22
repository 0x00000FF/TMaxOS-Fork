#!/bin/bash

#    Copyright 2012 Canonical Ltd.
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

for ipv6 in yes
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

        echo "TESTING RGS (limit to/from)" >> $TESTTMP/result
	do_cmd "0" limit 22/tcp
	do_cmd "0" limit from any port 24 proto udp
	do_cmd "0" limit in on eth1 to any port 23
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

	echo "TESTING ARGS (delete allow/deny to/from)" >> $TESTTMP/result
	do_cmd "0" delete limit 22/tcp
	do_cmd "0" delete limit from any port 24 proto udp
	do_cmd "0" delete limit in on eth1 to any port 23
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
done


echo "Testing status numbered" >> $TESTTMP/result
for ipv6 in yes
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

	do_cmd "0" limit 22/tcp
	do_cmd "0" limit from any port 24 proto udp
	do_cmd "0" limit in on eth1 to any port 23
	do_cmd "0" status numbered

	do_cmd "0" delete limit 22/tcp
	do_cmd "0" delete limit from any port 24 proto udp
	do_cmd "0" delete limit in on eth1 to any port 23
	do_cmd "0" status numbered
done


echo "Verify secondary limit chains" >> $TESTTMP/result
for l in off on low medium high full; do
    do_cmd "0" nostats logging $l
    do_cmd "0" nostats disable
    $TESTSTATE/ufw-init flush-all >/dev/null
    do_cmd "0" nostats enable
    for c in user-limit user-limit-accept ; do
        echo "$count: ip6tables -L ufw6-$c -n | egrep -q '0 references'" >> $TESTTMP/result
        ip6tables -L ufw6-$c -n | egrep -q '0 references' || {
            echo "'ip6tables -L ufw6-user-input -n' had more than 0 references"
            exit 1
        }
        echo "" >> $TESTTMP/result
        echo "" >> $TESTTMP/result
        let count=count+1
    done
done

cleanup

exit 0

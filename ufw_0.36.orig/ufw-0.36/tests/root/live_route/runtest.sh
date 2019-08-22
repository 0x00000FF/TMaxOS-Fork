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

# This isn't available everywhere, so we will test it later
sed -i "s/self.caps\['route limit'\]\['6'\] = True/self.caps['route limit']['6'] = False/" $TESTPATH/lib/python/ufw/backend.py

for ipv6 in yes no
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

	echo "TESTING ARGS (route allow/route deny to/from)" >> $TESTTMP/result
	do_cmd "0" route allow 53
	do_cmd "0" route allow 23/tcp
	do_cmd "0" route allow smtp
	do_cmd "0" route deny proto tcp to any port 80
	do_cmd "0" route deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" route allow from 10.0.0.0/8
	do_cmd "0" route allow from 172.16.0.0/12
	do_cmd "0" route allow from 192.168.0.0/16
	do_cmd "0" route deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" route allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" route limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" route deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" route deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

	echo "TESTING ARGS (delete route allow/route deny to/from)" >> $TESTTMP/result
	do_cmd "0" route delete allow 53
	do_cmd "0" route delete allow 23/tcp
	do_cmd "0" route delete allow smtp
	do_cmd "0" route delete deny proto tcp to any port 80
	do_cmd "0" route delete deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" route delete allow from 10.0.0.0/8
	do_cmd "0" route delete allow from 172.16.0.0/12
	do_cmd "0" route delete allow from 192.168.0.0/16
	do_cmd "0" route delete deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" route delete allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" route delete limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" route delete deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" route delete deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
done


echo "Checking route reject" >> $TESTTMP/result
for ipv6 in yes no
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable
	do_cmd "0" route reject 113
	do_cmd "0" route reject 114/tcp
	do_cmd "0" route reject 115/udp
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
	do_cmd "0" route delete reject 113
	do_cmd "0" route delete reject 114/tcp
	do_cmd "0" route delete reject 115/udp
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
done

echo "Checking flush builtins" >> $TESTTMP/result
for ans in yes no
do
        str="ufw_test_builtins"
        do_cmd "0" nostats disable
        sed -i "s/MANAGE_BUILTINS=.*/MANAGE_BUILTINS=$ans/" $TESTPATH/etc/default/ufw

        echo iptables -I FORWARD -j ACCEPT -m comment --comment $str >> $TESTTMP/result
        iptables -I FORWARD -j ACCEPT -m comment --comment $str >> $TESTTMP/result
        do_cmd "0" nostats enable
        iptables -n -L FORWARD | grep "$str" >> $TESTTMP/result
        iptables -D FORWARD -j ACCEPT -m comment --comment $str 2>/dev/null
done

echo "Testing status numbered" >> $TESTTMP/result
for ipv6 in yes no
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

	do_cmd "0" route allow 53
	do_cmd "0" route allow 23/tcp
	do_cmd "0" route allow smtp
	do_cmd "0" route deny proto tcp to any port 80
	do_cmd "0" route deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" route allow from 10.0.0.0/8
	do_cmd "0" route allow from 172.16.0.0/12
	do_cmd "0" route allow from 192.168.0.0/16
	do_cmd "0" route deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" route allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" route limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" route deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" route deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status numbered

	do_cmd "0" route delete allow 53
	do_cmd "0" route delete allow 23/tcp
	do_cmd "0" route delete allow smtp
	do_cmd "0" route delete deny proto tcp to any port 80
	do_cmd "0" route delete deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" route delete allow from 10.0.0.0/8
	do_cmd "0" route delete allow from 172.16.0.0/12
	do_cmd "0" route delete allow from 192.168.0.0/16
	do_cmd "0" route delete deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" route delete allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" route delete limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" route delete deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" route delete deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status numbered
done

in_if="fake0"
fake_if="$in_if"
out_if="fake1"
dmz_if="fake2"
echo "Testing interfaces" >> $TESTTMP/result
for ipv6 in yes no
do
    for i in "in" "out"; do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

        do_cmd "0" route allow $i on $fake_if
        do_cmd "1" null route deny $i on $fake_if:1
        do_cmd "0" route reject $i on $fake_if to 192.168.0.1 port 13
        do_cmd "0" route limit $i on $fake_if from 10.0.0.1 port 80
        do_cmd "0" route allow $i on $fake_if to 192.168.0.1 from 10.0.0.1
        do_cmd "0" route deny $i on $fake_if to 192.168.0.1 port 13 from 10.0.0.1
        do_cmd "0" route reject $i on $fake_if to 192.168.0.1 from 10.0.0.1 port 80
        do_cmd "0" route limit $i on $fake_if to 192.168.0.1 port 13 from 10.0.0.1 port 80

	do_cmd "0" route allow $i on $dmz_if log
	do_cmd "0" route allow $i on $fake_if log from 192.168.0.1 to 10.0.0.1 port 24 proto tcp
	do_cmd "0" route deny $i on $fake_if log-all from 192.168.0.1 to 10.0.0.1 port 25 proto tcp
	do_cmd "0" route allow $i on $fake_if to any app Samba

        # These hardcode in and out
        do_cmd "0" route allow in on $in_if out on $out_if from 192.168.0.1 port 25 to 10.0.0.1 port 25 proto tcp
        do_cmd "0" route allow in on $in_if out on $dmz_if

	do_cmd "0" status numbered
	do_cmd "0" route insert 8 allow $i on $dmz_if to any app Samba

	do_cmd "0" status numbered
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

	# delete what we added
        do_cmd "0" route delete allow $i on $fake_if
        do_cmd "0" route delete reject $i on $fake_if to 192.168.0.1 port 13
        do_cmd "0" route delete limit $i on $fake_if from 10.0.0.1 port 80
        do_cmd "0" route delete allow $i on $fake_if to 192.168.0.1 from 10.0.0.1
        do_cmd "0" route delete deny $i on $fake_if to 192.168.0.1 port 13 from 10.0.0.1
        do_cmd "0" route delete reject $i on $fake_if to 192.168.0.1 from 10.0.0.1 port 80
        do_cmd "0" route delete limit $i on $fake_if to 192.168.0.1 port 13 from 10.0.0.1 port 80

	do_cmd "0" route delete allow $i on $dmz_if log
	do_cmd "0" route delete allow $i on $fake_if log from 192.168.0.1 to 10.0.0.1 port 24 proto tcp
	do_cmd "0" route delete deny $i on $fake_if log-all from 192.168.0.1 to 10.0.0.1 port 25 proto tcp
	do_cmd "0" route delete allow $i on $fake_if to any app Samba
	do_cmd "0" route delete allow $i on $dmz_if to any app Samba
        do_cmd "0" route delete allow in on $in_if out on $out_if from 192.168.0.1 port 25 to 10.0.0.1 port 25 proto tcp
        do_cmd "0" route delete allow in on $in_if out on $dmz_if

	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
    done
done

echo "Compare enable and ufw-init" >> $TESTTMP/result
sed -i "s/IPV6=.*/IPV6=yes/" $TESTPATH/etc/default/ufw
do_cmd "0" nostats disable
do_cmd "0" nostats route allow 23/tcp
do_cmd "0" nostats logging medium
do_cmd "0" null enable
iptables-save | grep '^-' > $TESTTMP/ipt.enable
ip6tables-save | grep '^-' > $TESTTMP/ip6t.enable

do_cmd "0" null disable
iptables-save | grep '^-' > $TESTTMP/ipt.disable
ip6tables-save | grep '^-' > $TESTTMP/ip6t.disable

sed -i 's/^ENABLED=no/ENABLED=yes/' $TESTPATH/etc/ufw/ufw.conf
do_extcmd "0" null $TESTPATH/lib/ufw/ufw-init start
iptables-save | grep '^-' > $TESTTMP/ipt.start
ip6tables-save | grep '^-' > $TESTTMP/ip6t.start

do_extcmd "0" null $TESTPATH/lib/ufw/ufw-init stop
iptables-save | grep '^-' > $TESTTMP/ipt.stop
ip6tables-save | grep '^-' > $TESTTMP/ip6t.stop

diff $TESTTMP/ipt.enable $TESTTMP/ipt.start || {
	echo "'ufw enable' and 'ufw-init start' are different"
	exit 1
}

diff $TESTTMP/ip6t.enable $TESTTMP/ip6t.start || {
	echo "'ufw enable' and 'ufw-init start' are different (ipv6)"
	exit 1
}

diff $TESTTMP/ipt.disable $TESTTMP/ipt.stop || {
	echo "'ufw disable' and 'ufw-init stop' are different"
	exit 1
}

diff $TESTTMP/ip6t.disable $TESTTMP/ip6t.stop || {
	echo "'ufw disable' and 'ufw-init stop' are different (ipv6)"
	exit 1
}
do_cmd "0" nostats enable
do_cmd "0" nostats route delete allow 23/tcp
do_cmd "0" nostats logging low
do_cmd "0" nostats disable
sed -i "s/IPV6=.*/IPV6=no/" $TESTPATH/etc/default/ufw

echo "Delete by number" >> $TESTTMP/result
for ipv6 in yes no
do
    echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
    sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
    do_cmd "0" nostats disable
    do_cmd "0" nostats enable

    for i in 1 2 3 4; do
        do_cmd "0" nostats route allow $i
    done

    grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
    if [ "$ipv6" = "yes" ]; then
        grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
    fi

    for i in 4 3 2 1; do
        grep -q "^### tuple ### route:allow any $i " $TESTCONFIG/user.rules || {
            echo "Failed: Could not find port '$i' user.rules" >> $TESTTMP/result
            exit 1
        }
        if [ "$ipv6" = "yes" ]; then
            grep -q "^### tuple ### route:allow any $i " $TESTCONFIG/user6.rules || {
                echo "Failed: Could not find port '$i' user6.rules" >> $TESTTMP/result
                exit 1
            }
        fi

        if [ "$ipv6" = "yes" ]; then
            do_cmd "0" null --force delete $((i+i))
            grep -v -q "^### tuple ### route:allow any $i " $TESTCONFIG/user6.rules || {
                echo "Failed: Found port '$i' user6.rules" >> $TESTTMP/result
                exit 1
            }
            grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
        fi
        do_cmd "0" null --force delete $i
        grep -v -q "^### tuple ### route:allow any $i " $TESTCONFIG/user.rules || {
            echo "Failed: Found port '$i' user.rules" >> $TESTTMP/result
            exit 1
        }
        grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
    done
done
grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Show added" >> $TESTTMP/result
for ipv6 in yes no
do
    echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
    sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
    do_cmd "0" nostats disable
    do_cmd "0" nostats enable
    do_cmd "0" nostats route limit 13/tcp
    if [ "$ipv6" = "yes" ]; then
        do_cmd "0" nostats route allow in on $in_if to 2001::211:aaaa:bbbb:d54c port 123 proto tcp
    fi
    do_cmd "0" nostats route deny Samba
    do_cmd "0" show added
    do_cmd "0" nostats route delete limit 13/tcp
    if [ "$ipv6" = "yes" ]; then
        do_cmd "0" nostats route delete allow in on $in_if to 2001::211:aaaa:bbbb:d54c port 123 proto tcp
    fi
    do_cmd "0" nostats route delete deny Samba
    do_cmd "0" show added
done
do_cmd "0" nostats disable

echo "Checking status" >> $TESTTMP/result
for default in allow deny reject ; do
    for ipv6 in yes no
    do
        echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
        sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
        for forward in 0 1 ; do
            echo "Running: sysctl -w net.ipv4.ip_forward=$forward" >> $TESTTMP/result
            sysctl -w net.ipv4.ip_forward=$forward >/dev/null

            if [ "$ipv6" = "yes" ]; then
                echo "Running: sysctl -w net.ipv6.conf.default.forwarding=$forward" >> $TESTTMP/result
                sysctl -w net.ipv6.conf.default.forwarding=$forward >/dev/null
                echo "Running: sysctl -w net.ipv6.conf.all.forwarding=$forward" >> $TESTTMP/result
                sysctl -w net.ipv6.conf.all.forwarding=$forward >/dev/null
            fi

            do_cmd "0" nostats disable
            do_cmd "0" default $default routed
            do_cmd "0" nostats enable
            do_cmd "0" status verbose
        done
    done
done


cleanup

exit 0

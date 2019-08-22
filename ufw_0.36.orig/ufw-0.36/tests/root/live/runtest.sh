#!/bin/bash

#    Copyright 2008-2016 Canonical Ltd.
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
sed -i "s/self.caps\['limit'\]\['6'\] = True/self.caps['limit']['6'] = False/" $TESTPATH/lib/python/ufw/backend.py

for ipv6 in yes no
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

	echo "TESTING ARGS (logging)" >> $TESTTMP/result
	do_cmd "0"  logging on
	grep -h "LOG" `ls $TESTPATH/etc/ufw/*.rules` >> $TESTTMP/result
	do_cmd "0"  logging off
	grep -h "LOG" `ls $TESTPATH/etc/ufw/*.rules` >> $TESTTMP/result

	echo "TESTING ARGS (allow/deny to/from)" >> $TESTTMP/result
	do_cmd "0" allow 53
	do_cmd "0" allow 23/tcp
	do_cmd "0" allow smtp
	do_cmd "0" deny proto tcp to any port 80
	do_cmd "0" deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" allow from 10.0.0.0/8
	do_cmd "0" allow from 172.16.0.0/12
	do_cmd "0" allow from 192.168.0.0/16
	do_cmd "0" deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

	echo "TESTING ARGS (delete allow/deny to/from)" >> $TESTTMP/result
	do_cmd "0" delete allow 53
	do_cmd "0" delete allow 23/tcp
	do_cmd "0" delete allow smtp
	do_cmd "0" delete deny proto tcp to any port 80
	do_cmd "0" delete deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" delete allow from 10.0.0.0/8
	do_cmd "0" delete allow from 172.16.0.0/12
	do_cmd "0" delete allow from 192.168.0.0/16
	do_cmd "0" delete deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" delete allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" delete limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" delete deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" delete deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
done


echo "Checking status" >> $TESTTMP/result
do_cmd "0" null status
do_cmd "0" null status verbose
do_cmd "0" null status numbered

echo "Checking reject" >> $TESTTMP/result
for ipv6 in yes no
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable
	do_cmd "0" reject 113
	do_cmd "0" reject 114/tcp
	do_cmd "0" reject 115/udp
	do_cmd "0" status
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
	do_cmd "0" delete reject 113
	do_cmd "0" delete reject 114/tcp
	do_cmd "0" delete reject 115/udp
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

        echo iptables -I INPUT -j ACCEPT -m comment --comment $str >> $TESTTMP/result
        iptables -I INPUT -j ACCEPT -m comment --comment $str >> $TESTTMP/result
        do_cmd "0" nostats enable
        iptables -n -L INPUT | grep "$str" >> $TESTTMP/result
        iptables -D INPUT -j ACCEPT -m comment --comment $str 2>/dev/null
done

echo "Testing status numbered" >> $TESTTMP/result
for ipv6 in yes no
do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

	do_cmd "0" allow 53
	do_cmd "0" allow 23/tcp
	do_cmd "0" allow smtp
	do_cmd "0" deny proto tcp to any port 80
	do_cmd "0" deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" allow from 10.0.0.0/8
	do_cmd "0" allow from 172.16.0.0/12
	do_cmd "0" allow from 192.168.0.0/16
	do_cmd "0" deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status numbered

	do_cmd "0" delete allow 53
	do_cmd "0" delete allow 23/tcp
	do_cmd "0" delete allow smtp
	do_cmd "0" delete deny proto tcp to any port 80
	do_cmd "0" delete deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
	do_cmd "0" delete allow from 10.0.0.0/8
	do_cmd "0" delete allow from 172.16.0.0/12
	do_cmd "0" delete allow from 192.168.0.0/16
	do_cmd "0" delete deny proto udp from 1.2.3.4 to any port 514
	do_cmd "0" delete allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469
	do_cmd "0" delete limit 13/tcp
	if [ "$ipv6" = "yes" ]; then
		do_cmd "0" delete deny proto tcp from 2001:db8::/32 to any port 25
		do_cmd "0" delete deny from 2001:db8::/32 port 26 to 2001:db8:3:4:5:6:7:8
	fi
	do_cmd "0" status numbered
done

echo "Testing interfaces" >> $TESTTMP/result
for ipv6 in yes no
do
    for i in "in" "out"; do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

        do_cmd "0" allow $i on eth1
        do_cmd "1" null deny $i on eth1:1
        do_cmd "0" reject $i on eth1 to 192.168.0.1 port 13
        do_cmd "0" limit $i on eth1 from 10.0.0.1 port 80
        do_cmd "0" allow $i on eth1 to 192.168.0.1 from 10.0.0.1
        do_cmd "0" deny $i on eth1 to 192.168.0.1 port 13 from 10.0.0.1
        do_cmd "0" reject $i on eth1 to 192.168.0.1 from 10.0.0.1 port 80
        do_cmd "0" limit $i on eth1 to 192.168.0.1 port 13 from 10.0.0.1 port 80

	do_cmd "0" allow $i on eth0 log
	do_cmd "0" allow $i on eth0 log from 192.168.0.1 to 10.0.0.1 port 24 proto tcp
	do_cmd "0" deny $i on eth0 log-all from 192.168.0.1 to 10.0.0.1 port 25 proto tcp
	do_cmd "0" allow $i on eth0 to any app Samba

	do_cmd "0" status numbered
	do_cmd "0" insert 8 allow $i on eth2 to any app Samba

	do_cmd "0" status numbered
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

	# delete what we added
        do_cmd "0" delete allow $i on eth1
        do_cmd "0" delete reject $i on eth1 to 192.168.0.1 port 13
        do_cmd "0" delete limit $i on eth1 from 10.0.0.1 port 80
        do_cmd "0" delete allow $i on eth1 to 192.168.0.1 from 10.0.0.1
        do_cmd "0" delete deny $i on eth1 to 192.168.0.1 port 13 from 10.0.0.1
        do_cmd "0" delete reject $i on eth1 to 192.168.0.1 from 10.0.0.1 port 80
        do_cmd "0" delete limit $i on eth1 to 192.168.0.1 port 13 from 10.0.0.1 port 80

	do_cmd "0" delete allow $i on eth0 log
	do_cmd "0" delete allow $i on eth0 log from 192.168.0.1 to 10.0.0.1 port 24 proto tcp
	do_cmd "0" delete deny $i on eth0 log-all from 192.168.0.1 to 10.0.0.1 port 25 proto tcp
	do_cmd "0" delete allow $i on eth0 to any app Samba
	do_cmd "0" delete allow $i on eth2 to any app Samba

	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
    done
done

echo "Compare enable and ufw-init" >> $TESTTMP/result
sed -i "s/IPV6=.*/IPV6=yes/" $TESTPATH/etc/default/ufw
do_cmd "0" nostats disable
do_cmd "0" nostats allow 23/tcp
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
do_cmd "0" nostats delete allow 23/tcp
do_cmd "0" nostats logging low
do_cmd "0" nostats disable
sed -i "s/IPV6=.*/IPV6=no/" $TESTPATH/etc/default/ufw

echo "Verify toplevel chains" >> $TESTTMP/result
for l in off on low medium high full; do
    do_cmd "0" nostats logging $l
    do_cmd "0" nostats disable
    $TESTSTATE/ufw-init flush-all >/dev/null
    do_cmd "0" nostats enable
    for b in INPUT OUTPUT FORWARD; do
        for c in before-logging before after after-logging reject track ; do
            suffix=`echo $b | tr [A-Z] [a-z]`
            echo "$count: iptables -L $b -n | egrep -q 'ufw-$c-$suffix'" >> $TESTTMP/result
            iptables -L $b -n | egrep -q "ufw-$c-$suffix" || {
                echo "'iptables -L $b -n' does not contain 'ufw-$c-$suffix'"
                exit 1
            }
            echo "" >> $TESTTMP/result
            echo "" >> $TESTTMP/result
            let count=count+1
        done
    done
done

echo "Verify secondary chains" >> $TESTTMP/result
for l in off on low medium high full; do
    do_cmd "0" nostats logging $l
    do_cmd "0" nostats disable
    $TESTSTATE/ufw-init flush-all >/dev/null
    do_cmd "0" nostats enable
    for c in logging-deny not-local user-forward user-input user-output skip-to-policy-input ; do
        echo "$count: ! iptables -L ufw-$c -n | egrep -q '0 references'" >> $TESTTMP/result
        iptables -L ufw-$c -n | egrep -q '0 references' && {
            echo "'iptables -L ufw-user-input -n' had 0 references"
            exit 1
        }
        echo "" >> $TESTTMP/result
        echo "" >> $TESTTMP/result
        let count=count+1
    done
    for c in logging-allow user-limit user-limit-accept user-logging-forward user-logging-input user-logging-output skip-to-policy-output skip-to-policy-forward ; do
        echo "$count: iptables -L ufw-$c -n | egrep -q '0 references'" >> $TESTTMP/result
        iptables -L ufw-$c -n | egrep -q '0 references' || {
            echo "'iptables -L ufw-user-input -n' had more than 0 references"
            exit 1
        }
        echo "" >> $TESTTMP/result
        echo "" >> $TESTTMP/result
        let count=count+1
    done
done
do_cmd "0" nostats logging on
do_cmd "0" nostats disable

echo "'Resource temporarily unavailable' test" >> $TESTTMP/result
do_cmd "0" nostats disable
$TESTSTATE/ufw-init flush-all >/dev/null
do_cmd "0" nostats allow 13/tcp
do_cmd "0" nostats enable
$TESTSTATE/ufw-init stop >/dev/null
for i in `seq 1 25`; do
    echo "$count: ufw-init start/flush-all" >> $TESTTMP/result
    $TESTSTATE/ufw-init start >/dev/null || {
        echo "'ufw-init start' failed"
        exit 1
    }
    $TESTSTATE/ufw-init flush-all >/dev/null
    echo "" >> $TESTTMP/result
    echo "" >> $TESTTMP/result
    let count=count+1
done
do_cmd "0" nostats enable
do_cmd "0" nostats delete allow 13/tcp

echo "Reset test" >> $TESTTMP/result
do_cmd "0" nostats enable
do_cmd "0" nostats allow 12345
let rules_num="0"
for i in `ls $TESTPATH/etc/ufw/*.rules` ; do
    let rules_num=rules_num+1
done
do_cmd "0" null reset

let rules_bak_num="0"
for i in `ls $TESTPATH/etc/ufw/*.rules.2*` ; do
    let rules_bak_num=rules_bak_num+1
done
if [ "$rules_num" != "$rules_bak_num" ]; then
    echo "'ufw-init reset' failed ('$rules_num' != '$rules_bak_num')" >> $TESTTMP/result
    exit 1
fi
iptables -L ufw-user-input -n >/dev/null 2>&1 && {
    echo "Failed: found 'ufw-user-input', still running." >> $TESTTMP/result
    exit 1
}
grep -v -q 12345 $TESTCONFIG/user.rules || {
    echo "Failed: found '12345' in user.rules" >> $TESTTMP/result
    exit 1
}

echo "Show" >> $TESTTMP/result
for ipv6 in yes no
do
    echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
    sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
    do_cmd "0" nostats disable
    do_cmd "0" nostats enable
    cmds="raw builtins before-rules user-rules after-rules logging-rules listening"
    for i in $cmds; do
        do_cmd "0" null show $i
    done
done
do_cmd "0" nostats disable

echo "Delete by number" >> $TESTTMP/result
for ipv6 in yes no
do
    echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
    sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
    do_cmd "0" nostats disable
    do_cmd "0" nostats enable

    for i in 1 2 3 4; do
        do_cmd "0" nostats allow $i
    done

    grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
    if [ "$ipv6" = "yes" ]; then
        grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
    fi

    for i in 4 3 2 1; do
        grep -q "^### tuple ### allow any $i " $TESTCONFIG/user.rules || {
            echo "Failed: Could not find port '$i' user.rules" >> $TESTTMP/result
            exit 1
        }
        if [ "$ipv6" = "yes" ]; then
            grep -q "^### tuple ### allow any $i " $TESTCONFIG/user6.rules || {
                echo "Failed: Could not find port '$i' user6.rules" >> $TESTTMP/result
                exit 1
            }
        fi

        if [ "$ipv6" = "yes" ]; then
            do_cmd "0" null --force delete $((i+i))
            grep -v -q "^### tuple ### allow any $i " $TESTCONFIG/user6.rules || {
                echo "Failed: Found port '$i' user6.rules" >> $TESTTMP/result
                exit 1
            }
            grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
        fi
        do_cmd "0" null --force delete $i
        grep -v -q "^### tuple ### allow any $i " $TESTCONFIG/user.rules || {
            echo "Failed: Found port '$i' user.rules" >> $TESTTMP/result
            exit 1
        }
        grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
    done
done
grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Testing interface with '+'" >> $TESTTMP/result
for ipv6 in yes no
do
    for i in "in" "out"; do
	echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
	sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
	do_cmd "0" nostats disable
	do_cmd "0" nostats enable

        do_cmd "0" allow $i on lo+
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

	# delete what we added
        do_cmd "0" delete allow $i on lo+
	grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
	grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
    done
done
do_cmd "0" nostats disable

echo "Show added" >> $TESTTMP/result
for ipv6 in yes no
do
    echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
    sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
    do_cmd "0" nostats disable
    do_cmd "0" nostats enable
    do_cmd "0" nostats limit 13/tcp
    if [ "$ipv6" = "yes" ]; then
        do_cmd "0" nostats allow in on eth0 to 2001::211:aaaa:bbbb:d54c port 123 proto tcp
    fi
    do_cmd "0" nostats deny Samba
    do_cmd "0" show added
    do_cmd "0" nostats delete limit 13/tcp
    if [ "$ipv6" = "yes" ]; then
        do_cmd "0" nostats delete allow in on eth0 to 2001::211:aaaa:bbbb:d54c port 123 proto tcp
    fi
    do_cmd "0" nostats delete deny Samba
    do_cmd "0" show added
done
do_cmd "0" nostats disable

echo "Prepend" >> $TESTTMP/result
for ipv6 in yes no
do
    echo "Setting IPV6 to $ipv6" >> $TESTTMP/result
    sed -i "s/IPV6=.*/IPV6=$ipv6/" $TESTPATH/etc/default/ufw
    do_cmd "0" nostats disable
    do_cmd "0" nostats enable

    do_cmd "0" nostats allow 22/tcp
    do_cmd "0" nostats allow from 1.2.3.4
    if [ "$ipv6" = "yes" ]; then
        do_cmd "0" nostats allow from 2001:db8::/32
        do_cmd "0" prepend deny from 2a02:2210:12:a:b820:fff:fea2:25d1
    fi
    do_cmd "0" prepend deny from 6.7.8.9
    grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
    grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result

    # delete what we added
    do_cmd "0" nostats delete allow 22/tcp
    do_cmd "0" nostats delete allow from 1.2.3.4
    if [ "$ipv6" = "yes" ]; then
        do_cmd "0" nostats delete allow from 2001:db8::/32
        do_cmd "0" delete deny from 2a02:2210:12:a:b820:fff:fea2:25d1
    fi
    do_cmd "0" delete deny from 6.7.8.9
    grep -A2 "tuple" $TESTCONFIG/user.rules >> $TESTTMP/result
    grep -A2 "tuple" $TESTCONFIG/user6.rules >> $TESTTMP/result
done

cleanup

exit 0

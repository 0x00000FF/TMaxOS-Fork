#!/bin/bash

#    Copyright 2008-2009 Canonical Ltd.
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
sed -i 's/IPV6=no/IPV6=yes/' $TESTPATH/etc/default/ufw

echo "Man page" >> $TESTTMP/result
do_cmd "0" --dry-run allow 53
do_cmd "0" --dry-run allow 25/tcp
do_cmd "0" --dry-run allow smtp
do_cmd "0" --dry-run deny proto tcp to any port 80
do_cmd "0" --dry-run deny proto tcp from 10.0.0.0/8 to 192.168.0.1 port 25
do_cmd "0" --dry-run deny proto tcp from 2001:db8::/32 to any port 25
do_cmd "0" --dry-run deny 80/tcp
do_cmd "0" --dry-run delete deny 80/tcp
do_cmd "0" --dry-run limit daytime/tcp
do_cmd "0" --dry-run deny 53
do_cmd "0" --dry-run allow 80/tcp
do_cmd "0" --dry-run allow from 10.0.0.0/8
do_cmd "0" --dry-run allow from 172.16.0.0/12
do_cmd "0" --dry-run allow from 192.168.0.0/16
do_cmd "0" --dry-run deny proto udp from 1.2.3.4 to any port 514
do_cmd "0" --dry-run allow proto udp from 1.2.3.5 port 5469 to 1.2.3.4 port 5469

echo "Services SIMPLE" >> $TESTTMP/result
do_cmd "0" --dry-run allow smtp
do_cmd "0" --dry-run delete allow smtp
do_cmd "0" --dry-run allow smtp/tcp
do_cmd "0" --dry-run delete allow smtp/tcp
do_cmd "0" --dry-run allow tftp
do_cmd "0" --dry-run delete allow tftp
do_cmd "0" --dry-run allow tftp/udp
do_cmd "0" --dry-run delete allow tftp/udp
do_cmd "0" --dry-run allow daytime
do_cmd "0" --dry-run delete allow daytime
do_cmd "0" --dry-run allow daytime/tcp
do_cmd "0" --dry-run delete allow daytime/tcp
do_cmd "0" --dry-run allow daytime/udp
do_cmd "0" --dry-run delete allow daytime/udp

echo "Services EXTENDED" >> $TESTTMP/result
do_cmd "0" --dry-run allow to any port smtp from any port daytime
do_cmd "0" --dry-run delete allow to any port smtp from any port daytime
do_cmd "0" --dry-run allow to any port tftp from any port daytime
do_cmd "0" --dry-run delete allow to any port tftp from any port daytime
do_cmd "0" --dry-run allow to any port daytime from any port domain
do_cmd "0" --dry-run delete allow to any port daytime from any port domain

echo "Netmasks" >> $TESTTMP/result
do_cmd "0" --dry-run allow to 192.168.0.0/0
do_cmd "0" --dry-run allow to 192.168.0.0/16
do_cmd "0" --dry-run allow to 192.168.0.1/32
do_cmd "0" --dry-run allow from 192.168.0.0/0
do_cmd "0" --dry-run allow from 192.168.0.0/16
do_cmd "0" --dry-run allow from 192.168.0.1/32
do_cmd "0" --dry-run allow from 192.168.0.1/32 to 192.168.0.2/32

do_cmd "0" --dry-run allow to ::1/0
do_cmd "0" --dry-run allow to ::1/32
do_cmd "0" --dry-run allow to ::1/128
do_cmd "0" --dry-run allow from ::1/0
do_cmd "0" --dry-run allow from ::1/32
do_cmd "0" --dry-run allow from ::1/128
do_cmd "0" --dry-run allow from ::1/32 to ::1/16

echo "Netmasks (CIDR)" >> $TESTTMP/result
for i in $(seq 0 32); do
    do_cmd "0" null --dry-run allow to 192.168.0.1/$i
    do_cmd "0" null --dry-run allow from 192.168.0.1/$i
    do_cmd "0" null --dry-run allow from 192.168.0.1/$i to 192.168.0.2/$i
done

echo "TESTING VALID DOTTED" >> $TESTTMP/result
for i in $(seq 0 16 255); do
    do_cmd "0" null --dry-run allow from 10.0.0.1/255.255.255.$i
    do_cmd "0" null --dry-run allow from 10.0.0.1/255.255.$i.255
    do_cmd "0" null --dry-run allow from 10.0.0.1/255.$i.255.255
    do_cmd "0" null --dry-run allow from 10.0.0.1/$i.255.255.255
    do_cmd "0" null --dry-run allow from 10.0.0.1/$i.$i.$i.$i
done

echo "Multiports:" >> $TESTTMP/result
do_cmd "0" --dry-run allow from 192.168.0.1 port 34,35 proto tcp
do_cmd "0" --dry-run allow from 192.168.0.1 port 34,35:39 proto udp
do_cmd "0" --dry-run allow from 192.168.0.1 port 35:39 proto tcp
do_cmd "0" --dry-run allow from 192.168.0.1 port 210,23,21,15:19,13 proto udp
do_cmd "0" --dry-run allow from 192.168.0.1 port 34,35 to 192.168.0.2 port 24 proto tcp
do_cmd "0" --dry-run allow from 192.168.0.1 port 34,35:39 to 192.168.0.2 port 24 proto udp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 35:39 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24 proto tcp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 23,21,15:19,13 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24 proto udp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 34,35 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24:26 proto tcp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 34,35:39 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24:26 proto udp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 35:39 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24:26 proto tcp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 23,21,15:19,13 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24:26 proto udp

# simple syntax
for i in allow deny limit; do
    for j in tcp udp; do
        do_cmd "0" --dry-run $i 34,35/$j
        do_cmd "0" --dry-run $i 34,35:39/$j
        do_cmd "0" --dry-run $i 35:39/$j
        do_cmd "0" --dry-run $i 23,21,15:19,13/$j
    done
done

echo "Man page (reject)" >> $TESTTMP/result
do_cmd "0" --dry-run reject auth

echo "Reject" >> $TESTTMP/result
do_cmd "0" --dry-run reject to any port auth from any port smtp
do_cmd "0" --dry-run delete reject to any port auth from any port smtp
do_cmd "0" --dry-run reject to 10.0.0.1 port domain from 192.168.0.1 port auth
do_cmd "0" --dry-run delete reject to 10.0.0.1 port domain from 192.168.0.1 port auth
for i in any tcp udp ; do
    p="/$i"
    if [ "$i" = "any" ]; then
        p=""
    else
        do_cmd "0" --dry-run reject 23,21,15:19,13$p
    fi
    do_cmd "0" --dry-run reject 116$p
done
do_cmd "0" --dry-run reject from 2001:db8::/32 to any port 25
do_cmd "0" --dry-run reject to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 35:39 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24 proto tcp
do_cmd "0" --dry-run reject to 2001:db8:85a3:8d3:1319:8a2e:370:7341 port 35:39 from 2001:db8:85a3:8d3:1319:8a2e:370:7342 port 24 proto udp

echo "Insert" >> $TESTTMP/result
do_cmd "0" null allow to 127.0.0.1 port 13
do_cmd "0" null allow to 127.0.0.1 port 23
do_cmd "0" null allow to ::1 port 24
do_cmd "0" null allow to ::1 port 25

echo "ipv4 rule in ipv4 section" >> $TESTTMP/result
do_cmd "0" null insert 2 allow to 127.0.0.1 port 8888
cat $TESTCONFIG/user.rules >> $TESTTMP/result
cat $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "ipv6 rule in ipv6 section" >> $TESTTMP/result
do_cmd "0" null delete allow to 127.0.0.1 port 8888
do_cmd "0" null insert 4 allow to ::1 port 8888
cat $TESTCONFIG/user.rules >> $TESTTMP/result
cat $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "ipv6 rule in ipv4 section" >> $TESTTMP/result
do_cmd "0" null delete allow to ::1 port 8888
do_cmd "1" null insert 2 allow to ::1 port 8888

echo "ipv4 rule in ipv6 section" >> $TESTTMP/result
do_cmd "0" null delete allow to ::1 port 8888
do_cmd "1" null insert 4 allow to 127.0.0.1 port 8888

echo "'both' rule in ipv4 section" >> $TESTTMP/result
do_cmd "0" null delete allow to 127.0.0.1 port 8888
do_cmd "0" null insert 2 allow 8888
cat $TESTCONFIG/user.rules >> $TESTTMP/result
cat $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "'both' rule in ipv6 section" >> $TESTTMP/result
do_cmd "0" null delete allow 8888
do_cmd "0" null insert 4 allow log 8888
cat $TESTCONFIG/user.rules >> $TESTTMP/result
cat $TESTCONFIG/user6.rules >> $TESTTMP/result

do_cmd "0" null delete allow to 127.0.0.1 port 13
do_cmd "0" null delete allow to 127.0.0.1 port 23
do_cmd "0" null delete allow to ::1 port 24
do_cmd "0" null delete allow to ::1 port 25
do_cmd "0" null delete allow log 8888
cat $TESTCONFIG/user.rules >> $TESTTMP/result
cat $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Interfaces" >> $TESTTMP/result
for i in "in" "out" ; do
    do_cmd "0" null allow $i on eth0
    do_cmd "0" null allow $i on eth0 to 192.168.0.1
    do_cmd "0" null deny $i on eth0 from 192.168.0.1 port 13 proto tcp
    do_cmd "0" null reject $i on eth0 to 2001:db8:85a3:8d3:1319:8a2e:370:734
    do_cmd "0" null allow $i on eth0 from 2001:db8:85a3:8d3:1319:8a2e:370:734 port 13 proto tcp
    cat $TESTCONFIG/user.rules >> $TESTTMP/result
    cat $TESTCONFIG/user6.rules >> $TESTTMP/result
    do_cmd "0" null delete allow $i on eth0
    do_cmd "0" null delete allow $i on eth0 to 192.168.0.1
    do_cmd "0" null delete deny $i on eth0 from 192.168.0.1 port 13 proto tcp
    do_cmd "0" null delete reject $i on eth0 to 2001:db8:85a3:8d3:1319:8a2e:370:734
    do_cmd "0" null delete allow $i on eth0 from 2001:db8:85a3:8d3:1319:8a2e:370:734 port 13 proto tcp
    cat $TESTCONFIG/user.rules >> $TESTTMP/result
    cat $TESTCONFIG/user6.rules >> $TESTTMP/result
done

echo "IPSec" >> $TESTTMP/result
do_cmd "0" --dry-run allow to 10.0.0.1 proto esp
do_cmd "0" --dry-run allow to 10.0.0.1 from 10.4.0.0/16 proto esp
do_cmd "0" --dry-run allow to 10.0.0.1 proto ah
do_cmd "0" --dry-run allow to 10.0.0.1 from 10.4.0.0/16 proto ah
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:734 proto esp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:734 from 2001:db8::/32 proto esp
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:734 proto ah
do_cmd "0" --dry-run allow to 2001:db8:85a3:8d3:1319:8a2e:370:734 from 2001:db8::/32 proto ah
do_cmd "0" --dry-run allow to any proto esp
do_cmd "0" --dry-run allow to any proto ah

echo "Comments" >> $TESTTMP/result || exit 1
do_cmd "0" allow to 10.0.0.1 from 10.4.0.0/16 comment \"SSH\ port\"
do_cmd "0" allow to 2001:db8:85a3:8d3:1319:8a2e:370:734 from 2001:db8::/32 proto ah comment \"SSH\ port\"
do_cmd "0" delete allow to 10.0.0.1 from 10.4.0.0/16 comment \"SSH\ port\"
do_cmd "0" delete allow to 2001:db8:85a3:8d3:1319:8a2e:370:734 from 2001:db8::/32 proto ah comment \"SSH\ port\"
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Prepend" >> $TESTTMP/result
do_cmd "0" null allow 22/tcp
do_cmd "0" null allow from 1.2.3.4
do_cmd "0" null allow from 2001:db8::/32

do_cmd "0" null prepend deny from 2a02:2210:12:a:b820:fff:fea2:25d1
do_cmd "0" null prepend deny from 6.7.8.9
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

do_cmd "0" null delete allow 22/tcp
do_cmd "0" null delete allow from 1.2.3.4
do_cmd "0" null delete allow from 2001:db8::/32
do_cmd "0" null delete deny from 2a02:2210:12:a:b820:fff:fea2:25d1
do_cmd "0" null delete deny from 6.7.8.9
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Prepend (no rules)" >> $TESTTMP/result
do_cmd "0" null prepend allow 22/tcp
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result
do_cmd "0" null delete allow 22/tcp
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

do_cmd "0" null prepend allow to any app Samba
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result
do_cmd "0" null delete allow to any app Samba
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Prepend (multi rules)" >> $TESTTMP/result
do_cmd "0" null allow 22/tcp
do_cmd "0" null prepend deny 23
do_cmd "0" null prepend deny to any app Samba
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

do_cmd "0" null delete allow 22/tcp
do_cmd "0" null delete deny 23
do_cmd "0" null delete deny to any app Samba
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

echo "Prepend (example rules)" >> $TESTTMP/result
do_cmd "0" null allow 22/tcp
do_cmd "0" null allow from 1.2.3.4
do_cmd "0" null allow from 2001:db8::/32
do_cmd "0" null prepend deny from 2a02:2210:12:a:b820:fff:fea2:25d1
do_cmd "0" null prepend deny from 6.7.8.9
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result
do_cmd "0" null delete allow 22/tcp
do_cmd "0" null delete allow from 1.2.3.4
do_cmd "0" null delete allow from 2001:db8::/32
do_cmd "0" null delete deny from 2a02:2210:12:a:b820:fff:fea2:25d1
do_cmd "0" null delete deny from 6.7.8.9
cat $TESTCONFIG/user.rules $TESTCONFIG/user6.rules >> $TESTTMP/result

exit 0

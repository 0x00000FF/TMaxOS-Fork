#!/bin/bash

#    Copyright 2009-2012 Canonical Ltd.
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

echo "TESTING BAD DEFAULT POLICY" >> $TESTTMP/result
for i in INPUT OUTPUT FORWARD; do
    for j in "" ACCEP DRP REJCT ALLOW DENY LIMIT; do
        echo "Setting DEFAULT_${i}_POLICY to $j" >> $TESTTMP/result
        sed -i "s/DEFAULT_${i}_POLICY=.*/DEFAULT_${i}_POLICY=$j/" $TESTPATH/etc/default/ufw
        #do_cmd "1" null --dry-run status
        do_cmd "1" --dry-run status

        # put it back to something valid
        sed -i "s/DEFAULT_${i}_POLICY=.*/DEFAULT_${i}_POLICY=DROP/" $TESTPATH/etc/default/ufw
    done
done

exit 0

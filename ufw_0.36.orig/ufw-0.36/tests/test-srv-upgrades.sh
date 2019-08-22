#!/bin/sh
set -e

export SNAP_SKIP_INIT="yes"

testdir="$(mktemp -d)"
#shellcheck disable=SC2064
trap "rm -rf '$testdir'" EXIT HUP INT QUIT TERM


curdir="$(pwd)"
cd "$testdir"
tar -zxf "$curdir/tests/test-srv-upgrades-data.tar.gz"

echo "== Clean out everything"
rm -rf "$testdir"/var/snap/ufw/*/* "$testdir"/var/snap/ufw/*/.[eru]* "$testdir"/var/snap/ufw/8*

echo
echo "== Run srv on 23 for the first time"
SNAP=./snap/ufw/23 SNAP_DATA=./var/snap/ufw/23 SNAP_REVISION=23 "$curdir"/snap-files/bin/srv

echo
echo "== Convert 23 back to rules.orig"
mkdir "$testdir"/var/snap/ufw/23/.rules.orig
cp "$testdir"/snap/ufw/23/etc/ufw/*.rules "$testdir"/var/snap/ufw/23/.rules.orig
rm -f "$testdir"/var/snap/ufw/23/.rules.orig/user*rules
rm -rf "$testdir"/var/snap/ufw/23/.etc.last

echo
echo "== Simulate upgrade from 23 to 85"
cp -a "$testdir"/var/snap/ufw/23 "$testdir"/var/snap/ufw/85

echo
echo "== Run srv on 85"
SNAP=./snap/ufw/85 SNAP_DATA=./var/snap/ufw/85 SNAP_REVISION=85 "$curdir"/snap-files/bin/srv

echo
echo "== Simulate the user merged everything from 85"
rm -rf "$testdir"/var/snap/ufw/85/etc
cp -a "$testdir"/snap/ufw/85/etc "$testdir"/var/snap/ufw/85

echo
echo "== Simulate user change to after.rules"
echo "# some change" >> "$testdir"/var/snap/ufw/85/etc/ufw/after.rules

echo
echo "== Simulate upgrade from 85 to 86"
cp -a "$testdir"/var/snap/ufw/85 "$testdir"/var/snap/ufw/86

echo
echo "== Run srv on 86"
SNAP=./snap/ufw/86 SNAP_DATA=./var/snap/ufw/86 SNAP_REVISION=86 "$curdir"/snap-files/bin/srv

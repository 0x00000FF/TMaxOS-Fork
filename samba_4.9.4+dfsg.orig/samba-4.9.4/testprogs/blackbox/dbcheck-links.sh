#!/bin/sh

if [ $# -lt 1 ]; then
cat <<EOF
Usage: dbcheck-links.sh PREFIX RELEASE
EOF
exit 1;
fi

PREFIX_ABS="$1"
RELEASE="$2"
shift 2

. `dirname $0`/subunit.sh

. `dirname $0`/common-links.sh

dbcheck() {
    tmpfile=$PREFIX_ABS/$RELEASE/expected-dbcheck-link-output${1}.txt.tmp
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-dbcheck-output${1}2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $3 --fix --yes > $tmpfile
    if [ "$?" != "$2" ]; then
	return 1
    fi
    sort $tmpfile > $tmpfile.sorted
    sort $release_dir/expected-dbcheck-link-output${1}.txt > $tmpfile.expected
    diff -u $tmpfile.sorted $tmpfile.expected
    if [ "$?" != "0" ]; then
	return 1
    fi

    tmpldif2=$PREFIX_ABS/$RELEASE/expected-dbcheck-output${1}2.txt.tmp2
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif2

    diff -u $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_dangling() {
    dbcheck "" "1" ""
    return $?
}

dbcheck_one_way() {
    dbcheck "_one_way" "0" "CN=Configuration,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    return $?
}

dbcheck_clean() {
    tmpldif1=$PREFIX_ABS/$RELEASE/expected-dbcheck-output2.txt.tmp1

    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif1

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb
    if [ "$?" != "0" ]; then
	return 1
    fi
    tmpldif2=$PREFIX_ABS/$RELEASE/expected-dbcheck-output2.txt.tmp2
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -s base -b '' | grep highestCommittedUSN > $tmpldif2

    diff $tmpldif1 $tmpldif2
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-links-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-links-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_deleted_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-deleted-links-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=swimmers)(cn=leaders)(cn=helpers))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted member > $tmpldif
    diff $tmpldif $release_dir/expected-deleted-links-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

check_expected_after_objects() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-objects-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(samaccountname=fred)(samaccountname=ddg)(samaccountname=usg)(samaccountname=user1)(samaccountname=user1x)(samaccountname=user2))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted samAccountName | grep sAMAccountName > $tmpldif
    diff $tmpldif $release_dir/expected-objects-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

duplicate_member() {
    # We use an exisiting group so we have a stable GUID in the
    # dbcheck output
    LDIF1=$(TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -b 'CN=Enterprise Admins,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' -s base --reveal --extended-dn member)
    DN=$(echo "${LDIF1}" | grep '^dn: ')
    MSG=$(echo "${LDIF1}" | grep -v '^dn: ' | grep -v '^#' | grep -v '^$')
    ldif=$PREFIX_ABS/${RELEASE}/duplicate-member-multi.ldif
    {
	echo "${DN}"
	echo "changetype: modify"
	echo "replace: member"
	echo "${MSG}"
	echo "${MSG}" | sed -e 's!RMD_LOCAL_USN=[1-9][0-9]*!RMD_LOCAL_USN=0!'
    } > $ldif

    TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_duplicate_member() {
    dbcheck "_duplicate_member" "1" ""
    return $?
}

check_expected_after_duplicate_links() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-duplicates-after-link-dbcheck.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=administrator)(cn=enterprise admins))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted memberOf member > $tmpldif
    diff $tmpldif $release_dir/expected-duplicates-after-link-dbcheck.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

missing_link_sid_corruption() {
    # Step1: add user "missingsidu1"
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption1.ldif
    cat > $ldif <<EOF
dn: CN=missingsidu1,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: user
samaccountname: missingsidu1
objectGUID: 0da8f25e-d110-11e8-80b7-3c970ec68461
objectSid: S-1-5-21-4177067393-1453636373-93818738-771
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    # Step2: add user "missingsidu2"
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption2.ldif
    cat > $ldif <<EOF
dn: CN=missingsidu2,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: user
samaccountname: missingsidu2
objectGUID: 66eb8f52-d110-11e8-ab9b-3c970ec68461
objectSid: S-1-5-21-4177067393-1453636373-93818738-772
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    # Step3: add group "missingsidg3" and add users as members
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption3.ldif
    cat > $ldif <<EOF
dn: CN=missingsidg3,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: group
samaccountname: missingsidg3
objectGUID: fd992424-d114-11e8-bb36-3c970ec68461
objectSid: S-1-5-21-4177067393-1453636373-93818738-773
member: CN=missingsidu1,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
member: CN=missingsidu2,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    # Step4: remove one user again, so that we have one deleted link
    #
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption4.ldif
    cat > $ldif <<EOF
dn: CN=missingsidg3,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: modify
delete: member
member: CN=missingsidu1,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step5: remove the SIDS from the links
    #
    LDIF1=$(TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -b 'CN=missingsidg3,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' -s base --reveal --extended-dn --show-binary member)
    DN=$(echo "${LDIF1}" | grep '^dn: ')
    MSG=$(echo "${LDIF1}" | grep -v '^dn: ' | grep -v '^#' | grep -v '^$')
    ldif=$PREFIX_ABS/${RELEASE}/missing_link_sid_corruption5.ldif
    {
	echo "${DN}"
	echo "changetype: modify"
	echo "replace: member"
	#echo "${MSG}"
	echo "${MSG}" | sed \
		-e 's!<SID=S-1-5-21-4177067393-1453636373-93818738-771>;!!g' \
		-e 's!<SID=S-1-5-21-4177067393-1453636373-93818738-772>;!!g' \
		-e 's!RMD_ADDTIME=[1-9][0-9]*!RMD_ADDTIME=123456789000000000!g' \
		-e 's!RMD_CHANGETIME=[1-9][0-9]*!RMD_CHANGETIME=123456789000000000!g' \
		| cat
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    return 0
}

dbcheck_missing_link_sid_corruption() {
    dbcheck "-missing-link-sid-corruption" "1" ""
    return $?
}

forward_link_corruption() {
    #
    # Step1: add a duplicate forward link from
    # "CN=Enterprise Admins" to "CN=Administrator"
    #
    LDIF1=$(TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb -b 'CN=Enterprise Admins,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp' -s base --reveal --extended-dn member)
    DN=$(echo "${LDIF1}" | grep '^dn: ')
    MSG=$(echo "${LDIF1}" | grep -v '^dn: ' | grep -v '^#' | grep -v '^$')
    ldif=$PREFIX_ABS/${RELEASE}/forward_link_corruption1.ldif
    {
	echo "${DN}"
	echo "changetype: modify"
	echo "replace: member"
	echo "${MSG}"
	echo "${MSG}" | sed -e 's!RMD_LOCAL_USN=[1-9][0-9]*!RMD_LOCAL_USN=0!'
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add user "dangling"
    #
    ldif=$PREFIX_ABS/${RELEASE}/forward_link_corruption2.ldif
    cat > $ldif <<EOF
dn: CN=dangling,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: user
samaccountname: dangling
objectGUID: fd8a04ac-cea0-4921-b1a6-c173e1155c22
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step3: add a dangling backlink from
    # "CN=dangling" to "CN=Enterprise Admins"
    #
    ldif=$PREFIX_ABS/${RELEASE}/forward_link_corruption3.ldif
    {
	echo "dn: CN=dangling,CN=users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
	echo "changetype: modify"
	echo "add: memberOf"
	echo "memberOf: <GUID=304ad703-468b-465e-9787-470b3dfd7d75>;<SID=S-1-5-21-4177067393-1453636373-93818738-519>;CN=Enterprise Admins,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp"
    } > $ldif

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb.d/DC%3DRELEASE-4-5-0-PRE1,DC%3DSAMBA,DC%3DCORP.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi
}

dbcheck_forward_link_corruption() {
    dbcheck "-forward-link-corruption" "1" ""
    return $?
}

check_expected_after_dbcheck_forward_link_corruption() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-after-dbcheck-forward-link-corruption.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(cn=dangling)(cn=enterprise admins))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted memberOf member > $tmpldif
    diff $tmpldif $release_dir/expected-after-dbcheck-forward-link-corruption.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

oneway_link_corruption() {
    #
    # Step1: add  OU "dangling-ou"
    #
    ldif=$PREFIX_ABS/${RELEASE}/oneway_link_corruption.ldif
    cat > $ldif <<EOF
dn: OU=dangling-ou,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: organizationalUnit
objectGUID: 20600e7c-92bb-492e-9552-f3ed7f8a2cad
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --relax $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step2: add  msExchConfigurationContainer "dangling-msexch"
    #
    ldif=$PREFIX_ABS/${RELEASE}/oneway_link_corruption2.ldif
    cat > $ldif <<EOF
dn: OU=dangling-from,DC=release-4-5-0-pre1,DC=samba,DC=corp
changetype: add
objectclass: organizationalUnit
seeAlso: OU=dangling-ou,DC=release-4-5-0-pre1,DC=samba,DC=corp
EOF

    out=$(TZ=UTC $ldbmodify -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb $ldif)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi

    #
    # Step3: rename dangling-ou to dangling-ou2
    #
    # Because this is a one-way link we don't fix it at runtime
    #
    out=$(TZ=UTC $ldbrename -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb OU=dangling-ou,DC=release-4-5-0-pre1,DC=samba,DC=corp OU=dangling-ou2,DC=release-4-5-0-pre1,DC=samba,DC=corp)
    if [ "$?" != "0" ]; then
	echo "ldbmodify returned:\n$out"
	return 1
    fi
}

dbcheck_oneway_link_corruption() {
    dbcheck "-oneway-link-corruption" "0" ""
    return $?
}

check_expected_after_dbcheck_oneway_link_corruption() {
    tmpldif=$PREFIX_ABS/$RELEASE/expected-after-dbcheck-oneway-link-corruption.ldif.tmp
    TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(|(ou=dangling-ou)(ou=dangling-ou2)(ou=dangling-from))' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --sorted seeAlso > $tmpldif
    diff $tmpldif $release_dir/expected-after-dbcheck-oneway-link-corruption.ldif
    if [ "$?" != "0" ]; then
	return 1
    fi
}

dbcheck_dangling_multi_valued() {

    $PYTHON $BINDIR/samba-tool dbcheck -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb --fix --yes
    if [ "$?" != "1" ]; then
	return 1
    fi
}

dangling_multi_valued_check_missing() {
    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi2)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`
    if [ $WORDS -ne 4 ]; then
        echo Got only $WORDS links for dangling-multi2
	return 1
    fi
    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi3)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`
    if [ $WORDS -ne 4 ]; then
        echo Got only $WORDS links for dangling-multi3
	return 1
    fi
}

dangling_multi_valued_check_equal_or_too_many() {
    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi1)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`
    if [ $WORDS -ne 4 ]; then
        echo Got $WORDS links for dangling-multi1
	return 1
    fi

    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=dangling-multi5)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`

    if [ $WORDS -ne 0 ]; then
        echo Got $WORDS links for dangling-multi5
	return 1
    fi

    WORDS=`TZ=UTC $ldbsearch -H tdb://$PREFIX_ABS/${RELEASE}/private/sam.ldb '(samaccountname=Administrator)' -s sub -b DC=release-4-5-0-pre1,DC=samba,DC=corp --show-deleted --reveal --sorted msDS-RevealedDSAs | grep msDS-RevealedDSAs | wc -l`

    if [ $WORDS -ne 2 ]; then
        echo Got $WORDS links for Administrator
	return 1
    fi
}


if [ -d $release_dir ]; then
    testit $RELEASE undump
    testit "add_two_more_users" add_two_more_users
    testit "add_four_more_links" add_four_more_links
    testit "remove_one_link" remove_one_link
    testit "remove_one_user" remove_one_user
    testit "move_one_user" move_one_user
    testit "add_dangling_link" add_dangling_link
    testit "add_dangling_backlink" add_dangling_backlink
    testit "add_deleted_dangling_backlink" add_deleted_dangling_backlink
    testit "revive_links_on_deleted_group" revive_links_on_deleted_group
    testit "revive_backlink_on_deleted_group" revive_backlink_on_deleted_group
    testit "add_deleted_target_link" add_deleted_target_link
    testit "add_deleted_target_backlink" add_deleted_target_backlink
    testit "dbcheck_dangling" dbcheck_dangling
    testit "dbcheck_clean" dbcheck_clean
    testit "check_expected_after_deleted_links" check_expected_after_deleted_links
    testit "check_expected_after_links" check_expected_after_links
    testit "check_expected_after_objects" check_expected_after_objects
    testit "duplicate_member" duplicate_member
    testit "dbcheck_duplicate_member" dbcheck_duplicate_member
    testit "check_expected_after_duplicate_links" check_expected_after_duplicate_links
    testit "duplicate_clean" dbcheck_clean
    testit "forward_link_corruption" forward_link_corruption
    testit "dbcheck_forward_link_corruption" dbcheck_forward_link_corruption
    testit "check_expected_after_dbcheck_forward_link_corruption" check_expected_after_dbcheck_forward_link_corruption
    testit "forward_link_corruption_clean" dbcheck_clean
    testit "oneway_link_corruption" oneway_link_corruption
    testit "dbcheck_oneway_link_corruption" dbcheck_oneway_link_corruption
    testit "check_expected_after_dbcheck_oneway_link_corruption" check_expected_after_dbcheck_oneway_link_corruption
    testit "oneway_link_corruption_clean" dbcheck_clean
    testit "dangling_one_way_link" dangling_one_way_link
    testit "dbcheck_one_way" dbcheck_one_way
    testit "dbcheck_clean2" dbcheck_clean
    testit "missing_link_sid_corruption" missing_link_sid_corruption
    testit "dbcheck_missing_link_sid_corruption" dbcheck_missing_link_sid_corruption
    testit "missing_link_sid_clean" dbcheck_clean
    testit "dangling_one_way_dn" dangling_one_way_dn
    testit "deleted_one_way_dn" deleted_one_way_dn
    testit "dbcheck_clean3" dbcheck_clean
    testit "add_dangling_multi_valued" add_dangling_multi_valued
    testit "dbcheck_dangling_multi_valued" dbcheck_dangling_multi_valued
    testit "dangling_multi_valued_check_missing" dangling_multi_valued_check_missing
    testit "dangling_multi_valued_check_equal_or_too_many" dangling_multi_valued_check_equal_or_too_many
    # Currently this cannot pass
    testit "dbcheck_dangling_multi_valued_clean" dbcheck_clean
else
    subunit_start_test $RELEASE
    subunit_skip_test $RELEASE <<EOF
no test provision
EOF

    subunit_start_test "tombstones_expunge"
    subunit_skip_test "tombstones_expunge" <<EOF
no test provision
EOF
fi

if [ -d $PREFIX_ABS/${RELEASE} ]; then
    rm -fr $PREFIX_ABS/${RELEASE}
fi

exit $failed

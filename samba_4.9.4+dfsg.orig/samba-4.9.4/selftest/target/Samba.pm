#!/usr/bin/perl
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU GPL, v3 or later.

package Samba;

use strict;
use target::Samba3;
use target::Samba4;
use POSIX;
use Cwd qw(abs_path);

sub new($$$$$) {
	my ($classname, $bindir, $ldap, $srcdir, $server_maxtime) = @_;

	my $self = {
	    samba3 => new Samba3($bindir, $srcdir, $server_maxtime),
	    samba4 => new Samba4($bindir, $ldap, $srcdir, $server_maxtime),
	};
	bless $self;
	return $self;
}

%Samba::ENV_DEPS = (%Samba3::ENV_DEPS, %Samba4::ENV_DEPS);
our %ENV_DEPS;

%Samba::ENV_TARGETS = (
	(map { $_ => "Samba3" } keys %Samba3::ENV_DEPS),
	(map { $_ => "Samba4" } keys %Samba4::ENV_DEPS),
);
our %ENV_TARGETS;

%Samba::ENV_NEEDS_AD_DC = (
	(map { $_ => 1 } keys %Samba4::ENV_DEPS)
);
our %ENV_NEEDS_AD_DC;
foreach my $env (keys %Samba3::ENV_DEPS) {
    $ENV_NEEDS_AD_DC{$env} = ($env =~ /^ad_/);
}

sub setup_env($$$)
{
	my ($self, $envname, $path) = @_;

	my $targetname = $ENV_TARGETS{$envname};
	if (not defined($targetname)) {
		warn("Samba can't provide environment '$envname'");
		return "UNKNOWN";
	}

	my %targetlookup = (
		"Samba3" => $self->{samba3},
		"Samba4" => $self->{samba4}
	);
	my $target = $targetlookup{$targetname};

	if (defined($target->{vars}->{$envname})) {
		return $target->{vars}->{$envname};
	}

	my @dep_vars;
	foreach(@{$ENV_DEPS{$envname}}) {
		my $vars = $self->setup_env($_, $path);
		if (defined($vars)) {
			push(@dep_vars, $vars);
		} else {
			warn("Failed setting up $_ as a dependency of $envname");
			return undef;
		}
	}

	$ENV{ENVNAME} = $envname;
	# Avoid hitting system krb5.conf -
	# An env that needs Kerberos will reset this to the real value.
	$ENV{KRB5_CONFIG} = "$path/no_krb5.conf";

	my $setup_name = $ENV_TARGETS{$envname}."::setup_".$envname;
	my $setup_sub = \&$setup_name;
	my $env = &$setup_sub($target, "$path/$envname", @dep_vars);

	if (not defined($env)) {
		warn("failed to start up environment '$envname'");
		return undef;
	}

	$target->{vars}->{$envname} = $env;
	$target->{vars}->{$envname}->{target} = $target;

	return $env;
}

sub bindir_path($$) {
	my ($object, $path) = @_;

	my $valpath = "$object->{bindir}/$path";

	return $valpath if (-f $valpath or -d $valpath);
	return $path;
}

sub nss_wrapper_winbind_so_path($) {
        my ($object) = @_;
	my $ret = $ENV{NSS_WRAPPER_WINBIND_SO_PATH};
        if (not defined($ret)) {
	    $ret = bindir_path($object, "shared/libnss_wrapper_winbind.so.2");
	    $ret = abs_path($ret);
	}
	return $ret;
}

sub copy_file_content($$)
{
	my ($in, $out) = @_;
	open(IN, "${in}") or die("failed to open in[${in}] for reading: $!");
	open(OUT, ">${out}") or die("failed to open out[${out}] for writing: $!");
	while(<IN>) {
		print OUT $_;
	}
	close(OUT);
	close(IN);
}

sub prepare_keyblobs($)
{
	my ($ctx) = @_;

	my $cadir = "$ENV{SRCDIR_ABS}/selftest/manage-ca/CA-samba.example.com";
	my $cacert = "$cadir/Public/CA-samba.example.com-cert.pem";
	my $cacrl_pem = "$cadir/Public/CA-samba.example.com-crl.pem";
	my $dcdnsname = "$ctx->{hostname}.$ctx->{dnsname}";
	my $dcdir = "$cadir/DCs/$dcdnsname";
	my $dccert = "$dcdir/DC-$dcdnsname-cert.pem";
	my $dckey_private = "$dcdir/DC-$dcdnsname-private-key.pem";
	my $adminprincipalname = "administrator\@$ctx->{dnsname}";
	my $admindir = "$cadir/Users/$adminprincipalname";
	my $admincert = "$admindir/USER-$adminprincipalname-cert.pem";
	my $adminkey_private = "$admindir/USER-$adminprincipalname-private-key.pem";
	my $pkinitprincipalname = "pkinit\@$ctx->{dnsname}";
	my $pkinitdir = "$cadir/Users/$pkinitprincipalname";
	my $pkinitcert = "$pkinitdir/USER-$pkinitprincipalname-cert.pem";
	my $pkinitkey_private = "$pkinitdir/USER-$pkinitprincipalname-private-key.pem";

	my $tlsdir = "$ctx->{tlsdir}";
	my $pkinitdir = "$ctx->{prefix_abs}/pkinit";
	#TLS and PKINIT crypto blobs
	my $dhfile = "$tlsdir/dhparms.pem";
	my $cafile = "$tlsdir/ca.pem";
	my $crlfile = "$tlsdir/crl.pem";
	my $certfile = "$tlsdir/cert.pem";
	my $keyfile = "$tlsdir/key.pem";
	my $admincertfile = "$pkinitdir/USER-$adminprincipalname-cert.pem";
	my $adminkeyfile = "$pkinitdir/USER-$adminprincipalname-private-key.pem";
	my $pkinitcertfile = "$pkinitdir/USER-$pkinitprincipalname-cert.pem";
	my $pkinitkeyfile = "$pkinitdir/USER-$pkinitprincipalname-private-key.pem";

	mkdir($tlsdir, 0700);
	mkdir($pkinitdir, 0700);
	my $oldumask = umask;
	umask 0077;

	# This is specified here to avoid draining entropy on every run
	# generate by
	# openssl dhparam -out dhparms.pem -text -2 8192
	open(DHFILE, ">$dhfile");
	print DHFILE <<EOF;
-----BEGIN DH PARAMETERS-----
MIIECAKCBAEAlcpjuJptCzC2bIIApLuyFLw2nODQUztqs/peysY9e3LgWh/xrc87
SWJNSUrqFJFh2m357WH0XGcTdTk0b/8aIYIWjbwEhWR/5hZ+1x2TDrX1awkYayAe
pr0arycmWHaAmhw+m+dBdj2O2jRMe7gn0ha85JALNl+Z3wv2q2eys8TIiQ2dbHPx
XvpMmlAv7QHZnpSpX/XgueQr6T3EYggljppZwk1fe4W2cxBjCv9w/Q83pJXMEVVB
WESEQPZC38v6hVIXIlF4J7jXjV3+NtCLL4nvsy0jrLEntyKz5OB8sNPRzJr0Ju2Y
yXORCSMMXMygP+dxJtQ6txzQYWyaCYN1HqHDZy3cFL9Qy8kTFqIcW56Lti2GsW/p
jSMzEOa1NevhKNFL3dSZJx5m+5ZeMvWXlCqXSptmVdbs5wz5jkMUm/E6pVfM5lyb
Ttlcq2iYPqnJz1jcL5xwhoufID8zSJCPJ7C0jb0Ngy5wLIUZfjXJUXxUyxTnNR9i
N9Sc+UkDvLxnCW+qzjyPXGlQU1SsJwMLWa2ZecL/uYE4bOdcN3g+5WHkevyDnXqR
+yy9x7sGXjBT3bRWK5tVHJWOi6eBu1hp39U6aK8oOJWiUt3vmC2qEdIsT6JaLNNi
YKrSfRGBf19IJBaagen1S19bb3dnmwoU1RaWM0EeJQW1oXOBg7zLisB2yuu5azBn
tse00+0nc+GbH2y+jP0sE7xil1QeilZl+aQ3tX9vL0cnCa+8602kXxU7P5HaX2+d
05pvoHmeZbDV85io36oF976gBYeYN+qAkTUMsIZhuLQDuyn0963XOLyn1Pm6SBrU
OkIZXW7WoKEuO/YSfizUIqXwmAMJjnEMJCWG51MZZKx//9Hsdp1RXSm/bRSbvXB7
MscjvQYWmfCFnIk8LYnEt3Yey40srEiS9xyZqdrvobxz+sU1XcqR38kpVf4gKASL
xURia64s4emuJF+YHIObyydazQ+6/wX/C+m+nyfhuxSO6j1janPwtYbU+Uj3TzeM
04K1mpPQpZcaMdZZiNiu7i8VJlOPKAz7aJT8TnMMF5GMyzyLpSMpc+NF9L/BSocV
/cUM4wQT2PTHrcyYzmTVH7c9bzBkuxqrwVB1BY1jitDV9LIYIVBglKcX88qrfHIM
XiXPAIwGclD59qm2cG8OdM9NA5pNMI119KuUAIJsUdgPbR1LkT2XTT15YVoHmFSQ
DlaWOXn4td031jr0EisX8QtFR7+/0Nfoni6ydFGs5fNH/L1ckq6FEO4OhgucJw9H
YRmiFlsQBQNny78vNchwZne3ZixkShtGW0hWDdi2n+h7St1peNJCNJjMbEhRsPRx
RmNGWh4AL8rho4RO9OBao0MnUdjbbffD+wIBAg==
-----END DH PARAMETERS-----
EOF
	close(DHFILE);

	if (! -e ${dckey_private}) {
		umask $oldumask;
		return;
	}

	copy_file_content(${cacert}, ${cafile});
	copy_file_content(${cacrl_pem}, ${crlfile});
	copy_file_content(${dccert}, ${certfile});
	copy_file_content(${dckey_private}, ${keyfile});
	if (-e ${adminkey_private}) {
		copy_file_content(${admincert}, ${admincertfile});
		copy_file_content(${adminkey_private}, ${adminkeyfile});
	}
	if (-e ${pkinitkey_private}) {
		copy_file_content(${pkinitcert}, ${pkinitcertfile});
		copy_file_content(${pkinitkey_private}, ${pkinitkeyfile});
	}

	# COMPAT stuff to be removed in a later commit
	my $kdccertfile = "$tlsdir/kdc.pem";
	copy_file_content(${dccert}, ${kdccertfile});

	umask $oldumask;
}

sub mk_krb5_conf($$)
{
	my ($ctx) = @_;

	unless (open(KRB5CONF, ">$ctx->{krb5_conf}")) {
	        warn("can't open $ctx->{krb5_conf}$?");
		return undef;
	}

	my $our_realms_stanza = mk_realms_stanza($ctx->{realm},
						 $ctx->{dnsname},
						 $ctx->{domain},
						 $ctx->{kdc_ipv4});
	print KRB5CONF "
#Generated krb5.conf for $ctx->{realm}

[libdefaults]
 default_realm = $ctx->{realm}
 dns_lookup_realm = false
 dns_lookup_kdc = true
 ticket_lifetime = 24h
 forwardable = yes
 allow_weak_crypto = yes
 # Set the grace clocskew to 5 seconds
 # This is especially required by samba3.raw.session krb5 and
 # reauth tests
 clockskew = 5
 # We are running on the same machine, do not correct
 # system clock differences
 kdc_timesync = 0

";

	if (defined($ctx->{krb5_ccname})) {
		print KRB5CONF "
 default_ccache_name = $ctx->{krb5_ccname}
";
	}


        if (defined($ctx->{supported_enctypes})) {
		print KRB5CONF "
 default_etypes = $ctx->{supported_enctypes}
 default_as_etypes = $ctx->{supported_enctypes}
 default_tgs_enctypes = $ctx->{supported_enctypes}
 default_tkt_enctypes = $ctx->{supported_enctypes}
 permitted_enctypes = $ctx->{supported_enctypes}
";
	}

	print KRB5CONF "
[realms]
 $our_realms_stanza
";


        if (defined($ctx->{tlsdir})) {
	       print KRB5CONF "

[appdefaults]
	pkinit_anchors = FILE:$ctx->{tlsdir}/ca.pem

[kdc]
	enable-pkinit = true
	pkinit_identity = FILE:$ctx->{tlsdir}/kdc.pem,$ctx->{tlsdir}/key.pem
	pkinit_anchors = FILE:$ctx->{tlsdir}/ca.pem

";
        }
	close(KRB5CONF);
}

sub mk_realms_stanza($$$$)
{
	my ($realm, $dnsname, $domain, $kdc_ipv4) = @_;
	my $lc_domain = lc($domain);

	my $realms_stanza = "
 $realm = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }
 $dnsname = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }
 $domain = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }
 $lc_domain = {
  kdc = $kdc_ipv4:88
  admin_server = $kdc_ipv4:88
  default_domain = $dnsname
 }

";
        return $realms_stanza;
}

sub mk_mitkdc_conf($$)
{
	# samba_kdb_dir is the path to mit_samba.so
	my ($ctx, $samba_kdb_dir) = @_;

	unless (open(KDCCONF, ">$ctx->{mitkdc_conf}")) {
	        warn("can't open $ctx->{mitkdc_conf}$?");
		return undef;
	}

	print KDCCONF "
# Generated kdc.conf for $ctx->{realm}

[kdcdefaults]
	kdc_ports = 88
	kdc_tcp_ports = 88

[realms]
	$ctx->{realm} = {
	}

	$ctx->{dnsname} = {
	}

	$ctx->{domain} = {
	}

[dbmodules]
	db_module_dir = $samba_kdb_dir

	$ctx->{realm} = {
		db_library = samba
	}

	$ctx->{dnsname} = {
		db_library = samba
	}

	$ctx->{domain} = {
		db_library = samba
	}

[logging]
	kdc = FILE:$ctx->{logdir}/mit_kdc.log
";

	close(KDCCONF);
}

sub get_interface($)
{
    my ($netbiosname) = @_;
    $netbiosname = lc($netbiosname);

    my %interfaces = ();
    $interfaces{"localnt4dc2"} = 3;
    $interfaces{"localnt4member3"} = 4;
    $interfaces{"localshare4"} = 5;

    $interfaces{"localktest6"} = 7;
    $interfaces{"maptoguest"} = 8;
    $interfaces{"localnt4dc9"} = 9;

    # 11-16 used by selftest.pl for client interfaces

    $interfaces{"addc_no_nss"} = 17;
    $interfaces{"addc_no_ntlm"} = 18;
    $interfaces{"idmapadmember"} = 19;
    $interfaces{"idmapridmember"} = 20;
    $interfaces{"localdc"} = 21;
    $interfaces{"localvampiredc"} = 22;
    $interfaces{"s4member"} = 23;
    $interfaces{"localrpcproxy"} = 24;
    $interfaces{"dc5"} = 25;
    $interfaces{"dc6"} = 26;
    $interfaces{"dc7"} = 27;
    $interfaces{"rodc"} = 28;
    $interfaces{"localadmember"} = 29;
    $interfaces{"addc"} = 30;
    $interfaces{"localsubdc"} = 31;
    $interfaces{"chgdcpass"} = 32;
    $interfaces{"promotedvdc"} = 33;
    $interfaces{"rfc2307member"} = 34;
    $interfaces{"fileserver"} = 35;
    $interfaces{"fakednsforwarder1"} = 36;
    $interfaces{"fakednsforwarder2"} = 37;
    $interfaces{"s4member_dflt"} = 38;
    $interfaces{"vampire2000dc"} = 39;
    $interfaces{"backupfromdc"} = 40;
    $interfaces{"restoredc"} = 41;
    $interfaces{"renamedc"} = 42;
    $interfaces{"labdc"} = 43;

    # update lib/socket_wrapper/socket_wrapper.c
    #  #define MAX_WRAPPED_INTERFACES 64
    # if you wish to have more than 64 interfaces

    if (not defined($interfaces{$netbiosname})) {
	die();
    }

    return $interfaces{$netbiosname};
}

sub cleanup_child($$)
{
    my ($pid, $name) = @_;

    if (!defined($pid)) {
        print STDERR "cleanup_child: pid not defined ... not calling waitpid\n";
        return -1;
    }

    my $childpid = waitpid($pid, WNOHANG);

    if ($childpid == 0) {
    } elsif ($childpid < 0) {
	printf STDERR "%s child process %d isn't here any more\n", $name, $pid;
	return $childpid;
    } elsif ($? & 127) {
	printf STDERR "%s child process %d, died with signal %d, %s coredump\n",
		$name, $childpid, ($? & 127),  ($? & 128) ? 'with' : 'without';
    } else {
	printf STDERR "%s child process %d exited with value %d\n", $name, $childpid, $? >> 8;
    }
    return $childpid;
}

sub random_domain_sid()
{
	my $domain_sid = "S-1-5-21-". int(rand(4294967295)) . "-" . int(rand(4294967295)) . "-" . int(rand(4294967295));
	return $domain_sid;
}

1;

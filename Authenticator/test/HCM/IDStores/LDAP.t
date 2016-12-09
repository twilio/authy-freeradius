#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Module::Load qw(load);
use Test::More;

my $ID_STORE = 'HCM::IDStores::LDAP';
load $ID_STORE;

$ID_STORE->initialize(
    config => {
        URI => 'ldaps://blizzard.hcmlabs.net:1636',
        # UseStartTLS => 1,
        CAFile => '/tmp/blizzard.cer',
        BindDN => 'cn=radadm,ou=IDCS,ou=People,dc=hcmlabs,dc=net',
        UserBaseDN => 'ou=IDCS,ou=People,dc=hcmlabs,dc=net',
        UserNameAttribute => 'uid',
        IDAttribute => 'authyId',
    },
    errors => {
        CannotOpenConnection => "Cannot open a connection to the LDAP server",
        MultipleUsersFound   => "Multiple LDAP users found with %s '%s'",
        MultipleIDsFound     => "Multiple Authy IDs found for LDAP user '%s'",
    },
);

say "Authy ID: ".$ID_STORE->get_authy_id('gmoore');

done_testing();


#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Module::Load qw(load);
use Test::More;

my $ID_STORE = 'Authy::IDStores::CSV';
load $ID_STORE;

$ID_STORE->initialize({
    File                 => '/tmp/users.csv',
    UserNameColumnNumber => 1,
    IDColumnNumber       => 2,
});

say "Authy ID: ".$ID_STORE->get_authy_id('gmoore');

done_testing();


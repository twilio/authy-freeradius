#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Test::More;
use Data::Dumper;

use_ok('Authy::AuthyState');
use Authy::AuthyState;
use_ok('Authy::Configuration');
use Authy::Configuration;

my $new_state = Authy::AuthyState->new(
    id => 12345678,
    reply_type => REPLY_TYPE_METHOD_DECISION,
    tries_remaining => 5,
);
print "new_state: ".Dumper($new_state);
say "new_state stringified: ".$new_state;

say pack 'H*', '0x41757468793a3a417574687953746174657b227265706c795f74797065223a302c226964223a31323334353637382c2274726965735f72656d61696e696e67223a357d';
my $state_from_string = Authy::AuthyState->load('0x41757468793a3a417574687953746174657b227265706c795f74797065223a302c226964223a31323334353637382c2274726965735f72656d61696e696e67223a357d');
print "state_from_string: ".Dumper($state_from_string);
say "state_from_string stringified: ".$state_from_string;

done_testing();


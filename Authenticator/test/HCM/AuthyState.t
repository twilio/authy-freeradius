#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Test::More;
use Data::Dumper;

use_ok('HCM::AuthyState');
use HCM::AuthyState;
use_ok('HCM::Configuration');
use HCM::Configuration;

my $new_state = HCM::AuthyState->new(
    id => 12345678,
    reply_type => REPLY_TYPE_METHOD_DECISION,
    tries_remaining => 5,
);
print "new_state: ".Dumper($new_state);
say "new_state stringified: ".$new_state;

say pack 'H*', '0x48434d3a3a41757468794d464153746174657b227265706c795f74797065223a302c226964223a32363235383339392c2274726965735f72656d61696e696e67223a317d';
#my $state_from_string = HCM::AuthyState->load('0x'.unpack('H*', cfg_radius_state_marker().'{"id":12345678,"reply_type":1,"tries_remaining":5}'));
my $state_from_string = HCM::AuthyState->load('0x48434d3a3a41757468794d464153746174657b227265706c795f74797065223a302c226964223a32363235383339392c2274726965735f72656d61696e696e67223a317d');
print "state_from_string: ".Dumper($state_from_string);
say "state_from_string stringified: ".$state_from_string;

done_testing();


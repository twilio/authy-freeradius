package radiusd;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Carp qw(croak);

use Exporter qw(import);
our @EXPORT = qw(radlog);

our %_LEVEL_NAMES = (
    1   => "DEBUG",
    2   => "AUTH",
    3   => "INFO",
    4   => "ERR",
    5   => "PROXY",
    6   => "ACCT",
    128 => "CONS",
);

sub radlog {
    my ($level, $msg) = @_;

    if (!defined $level) {
        croak "No logging level specified";
    }
    elsif (!defined $msg) {
        croak "No output message specified";
    }

    my $level_name = $_LEVEL_NAMES{$level};
    if (!defined $level) {
        croak "Invalid logging level $level";
    }
    say "rlm_perl: $level_name: $msg"
}

package Authy::AuthyState;

use 5.010;
use strict;
use warnings FATAL => 'all';
use overload '""' => \&stringify;

use Authy::Configuration;
use Authy::Text;
use Carp qw(croak);
use JSON qw(encode_json decode_json);
use Scalar::Util;

use Exporter qw(import);
our @EXPORT = qw(REPLY_TYPE_METHOD_DECISION REPLY_TYPE_OTP);

use constant _STATE_PREFIX => cfg_radius_state_marker();
use constant _ENCODED_STATE_PREFIX => '0x'.unpack('H*', _STATE_PREFIX);

# Reply type:
use constant {
    REPLY_TYPE_METHOD_DECISION => 0,
    REPLY_TYPE_OTP => 1,
};
our @_REPLY_TYPES = (REPLY_TYPE_METHOD_DECISION, REPLY_TYPE_OTP);

sub is_compatible_encoded_state {
    my ($encoded_state) = @_;
    return defined $encoded_state && substr($encoded_state, 0, length _ENCODED_STATE_PREFIX) eq _ENCODED_STATE_PREFIX;
}

sub load {
    my ($class, $encoded_state) = @_;
    croak "No encoded state specfied" unless defined $encoded_state;

    # Verify that the encoded state data is compatible.
    if (!is_compatible_encoded_state($encoded_state)) {
        croak "Incompatible state $encoded_state";
    }

    # Decode and validate the state data.
    my $state_data;
    eval {
        $state_data = decode_json(pack('H*', substr $encoded_state, length(_ENCODED_STATE_PREFIX)));
    };
    die err_invalid_state($encoded_state)."\n" if $@
        || !defined($state_data->{id} // $state_data->{tries_remaining} // $state_data->{reply_type})
        || $state_data->{id} !~ /^\d+$/
        || $state_data->{tries_remaining} !~ /^\d+$/
        || !($state_data->{reply_type} ~~ @_REPLY_TYPES);

    # Extract the state parameters.
    return $class->new(
        id => int $state_data->{id},
        tries_remaining => int $state_data->{tries_remaining},
        reply_type => int $state_data->{reply_type},
    );
}

sub new {
    my $class = shift;
    my %options = (
        id              => undef,
        tries_remaining => undef,
        reply_type      => undef,
        @_
    );

    my $self = {};
    bless $self, $class;

    $self->{_id} = _validate_id($options{id});
    $self->{_tries_remaining} = _validate_tries_remaining($options{tries_remaining});
    $self->{_reply_type} = _validate_reply_type($options{reply_type}) if defined $options{reply_type};
    return $self;
}

sub get_id {
    my ($self) = @_;
    return $self->{_id};
}

sub set_id {
    my ($self, $id) = @_;
    $self->{_id} = _validate_id($id);
}

sub _validate_id {
    my ($id) = @_;
    croak "No ID specified" unless defined $id;
    croak "Invalid ID '$id'" if ($id !~ /^\d+$/);
    return int $id;
}

sub get_reply_type {
    my ($self) = @_;
    return $self->{_reply_type};
}

sub set_reply_type {
    my ($self, $reply_type) = @_;
    $self->{_reply_type} = _validate_reply_type($reply_type);
}

sub _validate_reply_type {
    my ($reply_type) = @_;
    croak "No reply type specified" unless defined $reply_type;
    croak "Invalid reply type '$reply_type'" unless $reply_type ~~ @_REPLY_TYPES;
    return int $reply_type;
}

sub can_retry {
    my ($self) = @_;
    return $self->{_tries_remaining} > 0;
}

sub fail_try {
    my ($self) = @_;
    --$self->{_tries_remaining};
}

sub _validate_tries_remaining {
    my ($tries_remaining) = @_;
    croak "No remaining try count specified" unless defined $tries_remaining;
    croak "Invalid remaining try count '$tries_remaining'" if $tries_remaining !~ /^\d+$/;
    return int $tries_remaining;
}

sub stringify {
    my ($self) = @_;
    my $state_data = encode_json({
        id => $self->{_id},
        tries_remaining => $self->{_tries_remaining},
        reply_type => $self->{_reply_type},
    });
    return cfg_radius_state_marker().$state_data;
}

1;

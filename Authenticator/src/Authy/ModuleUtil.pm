package Authy::ModuleUtil;

use 5.010;
use strict;
use warnings FATAL => 'all';

eval "use radiusd"; # For local testing.

use Exporter qw(import);
our @EXPORT = qw(
    RLM_MODULE_REJECT
    RLM_MODULE_FAIL
    RLM_MODULE_OK
    RLM_MODULE_HANDLED
    RLM_MODULE_INVALID
    RLM_MODULE_USERLOCK
    RLM_MODULE_NOTFOUND
    RLM_MODULE_NOOP
    RLM_MODULE_UPDATED

    log_dbg
    log_auth
    log_info
    log_err
    log_proxy
    log_acct
);

# Module return codes:
use constant {
    RLM_MODULE_REJECT   => 0,
    RLM_MODULE_FAIL     => 1,
    RLM_MODULE_OK       => 2,
    RLM_MODULE_HANDLED  => 3,
    RLM_MODULE_INVALID  => 4,
    RLM_MODULE_USERLOCK => 5,
    RLM_MODULE_NOTFOUND => 6,
    RLM_MODULE_NOOP     => 7,
    RLM_MODULE_UPDATED  => 8,
};

# Logging levels:
use constant {
    L_DBG   => 1,
    L_AUTH  => 2,
    L_INFO  => 3,
    L_ERR   => 4,
    L_PROXY => 5,
    L_ACCT  => 6,
    L_CONS  => 128,
};

sub _log {
    my $level = shift;
    my $message = shift;
    my %options = @_;
    $options{cons} = 0 unless defined $options{cons};
    radiusd::radlog($options{cons} ? (L_CONS | $level) : $level, $message);
}

sub log_dbg {
    my ($message, %options) = @_;
    _log(L_DBG, $message, %options);
}

sub log_auth {
    my ($message, %options) = @_;
    _log(L_AUTH, $message, %options);
}

sub log_info {
    my ($message, %options) = @_;
    _log(L_INFO, $message, %options);
}

sub log_err {
    my ($message, %options) = @_;
    _log(L_ERR, $message, %options);
}

sub log_proxy {
    my ($message, %options) = @_;
    _log(L_PROXY, $message, %options);
}

sub log_acct {
    my ($message, %options) = @_;
    _log(L_ACCT, $message, %options);
}

1;

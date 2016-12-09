package HCM::ModuleUtil;

use 5.010;
use strict;
use warnings FATAL => 'all';

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

    L_DBG
    L_AUTH
    L_INFO
    L_ERR
    L_PROXY
    L_ACCT
    L_CONS
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

1;

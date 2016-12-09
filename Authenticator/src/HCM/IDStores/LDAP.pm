package HCM::IDStores::LDAP;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Carp qw(croak);
use HCM::ModuleUtil;
use HCM::Text;
use ResourcePool;
use ResourcePool::Factory::Net::LDAP;

eval "use radiusd"; # For local testing.

our $_CONNECTION_POOL;
our ($_USER_BASE_DN, $_USER_NAME_ATTRIBUTE, $_ID_ATTRIBUTE);
our ($_MSG, $_ERR);

# Configuration option names:
use constant {
    _OPT_URI                          => 'URI',
    _OPT_USE_START_TLS                => 'UseStartTLS',
    _OPT_VERIFY_HOSTNAME              => 'VerifyHostname',
    _OPT_CA_FILE                      => 'CAFile',
    _OPT_CA_PATH                      => 'CAPath',
    _OPT_BIND_DN                      => 'BindDN',
    _OPT_BIND_PASSWORD_ENV            => 'BindPasswordEnv',
    _OPT_USER_BASE_DN                 => 'UserBaseDN',
    _OPT_USER_NAME_ATTRIBUTE          => 'UserNameAttribute',
    _OPT_ID_ATTRIBUTE                 => 'IDAttribute',
    _OPT_INITIAL_CONNECTION_POOL_SIZE => 'InitialConnectionPoolSize',
    _OPT_MAX_CONNECTION_POOL_SIZE     => 'MaxConnectionPoolSize',
    _OPT_CONNECTION_RETRY_DELAY       => 'ConnectionRetryDelay',
};

# Default configuration values:
use constant {
    _DEF_URI                          => undef,
    _DEF_USE_START_TLS                => 0,
    _DEF_VERIFY_HOSTNAME              => 0,
    _DEF_CA_FILE                      => undef,
    _DEF_CA_PATH                      => undef,
    _DEF_BIND_DN                      => undef,
    _DEF_BIND_PASSWORD_ENV            => 'LDAP_BIND_PASSWORD',
    _DEF_USER_BASE_DN                 => '',
    _DEF_USER_NAME_ATTRIBUTE          => undef,
    _DEF_ID_ATTRIBUTE                 => undef,
    _DEF_INITIAL_CONNECTION_POOL_SIZE => 2,
    _DEF_MAX_CONNECTION_POOL_SIZE     => 5,
    _DEF_CONNECTION_RETRY_DELAY       => 0,
};

# Errors:
use constant {
    _ERR_ID_CANNOT_OPEN_CONNECTION => 'CannotOpenConnection',
    _ERR_ID_MULTIPLE_USERS_FOUND   => 'MultipleUsersFound',
    _ERR_ID_MULTIPLE_IDS_FOUND     => 'MultipleIDsFound',
};

sub initialize {
    shift; # Skip the class name
    my %params = (
        config   => {},
        messages => {},
        errors   => {},
        @_
    );

    my $config = $params{config};
    $_MSG = $params{messages};
    $_ERR = $params{errors};

    # Load the configuration options.
    my $uri = _get_value($config, _OPT_URI, _DEF_URI);
    my $use_ldaps = $uri =~ m"^ldaps://";
    my $use_start_tls = _get_value($config, _OPT_USE_START_TLS, _DEF_USE_START_TLS);
    my $verify_hostname = _get_value($config, _OPT_VERIFY_HOSTNAME, $use_ldaps || $use_start_tls, 0);
    my $ca_file = _get_value($config, _OPT_CA_FILE, _DEF_CA_FILE, 0);
    my $ca_path = _get_value($config, _OPT_CA_PATH, _DEF_CA_PATH, 0);
    my $bind_dn = _get_value($config, _OPT_BIND_DN, _DEF_BIND_DN);
    my $bind_password_env = _get_value($config, _OPT_BIND_PASSWORD_ENV, _DEF_BIND_PASSWORD_ENV);
    my $bind_password = $ENV{$bind_password_env};
    $_USER_BASE_DN = _get_value($config, _OPT_USER_BASE_DN, _DEF_USER_BASE_DN);
    $_USER_NAME_ATTRIBUTE = _get_value($config, _OPT_USER_NAME_ATTRIBUTE, _DEF_USER_NAME_ATTRIBUTE);
    $_ID_ATTRIBUTE = _get_value($config, _OPT_ID_ATTRIBUTE, _DEF_ID_ATTRIBUTE);
    my $initial_connection_pool_size = _get_value($config, _OPT_INITIAL_CONNECTION_POOL_SIZE, _DEF_INITIAL_CONNECTION_POOL_SIZE);
    my $max_connection_pool_size = _get_value($config, _OPT_MAX_CONNECTION_POOL_SIZE, _DEF_MAX_CONNECTION_POOL_SIZE);
    my $connection_retry_delay = _get_value($config, _OPT_CONNECTION_RETRY_DELAY, _DEF_CONNECTION_RETRY_DELAY);

    # Validate the configuration options.
    die "Cannot use StartTLS with an LDAPS URI\n" if $use_start_tls && $use_ldaps;
    die "No LDAP bind password specified\n" unless defined $bind_password;
    die "Invalid initial LDAP connection pool size '$initial_connection_pool_size'\n"
        unless $initial_connection_pool_size =~ /^\d+$/;
    die "Invalid max LDAP connection pool size '$max_connection_pool_size'\n" unless $max_connection_pool_size =~ /^\d+$/;
    die "Initial LDAP connection pool size must be less than or equal to the max LDAP connection pool size\n"
        unless $initial_connection_pool_size <= $max_connection_pool_size;
    die "Invalid LDAP connection retry delay '$connection_retry_delay'\n" unless $connection_retry_delay =~ /^\d+$/;

    # Ensure that the messages were loaded.
    _ensure_err($_ERR, _ERR_ID_CANNOT_OPEN_CONNECTION);
    _ensure_err($_ERR, _ERR_ID_MULTIPLE_IDS_FOUND);
    _ensure_err($_ERR, _ERR_ID_MULTIPLE_USERS_FOUND);

    # Create the connection pool.
    my $conn_factory;
    if ($use_start_tls) {
        $conn_factory = ResourcePool::Factory::Net::LDAP->new($uri);
        $conn_factory->start_tls(
            verify => $verify_hostname ? 'require' : 'none',
            cafile => $ca_file,
            capath => $ca_path,
        );
    }
    else {
        $conn_factory = ResourcePool::Factory::Net::LDAP->new(
            $uri,
            verify => $verify_hostname ? 'require' : 'none',
            cafile => $ca_file,
            capath => $ca_path,
        );
    }
    $conn_factory->bind($bind_dn, password => $bind_password);

    # Initialize the connection pool.
    radiusd::radlog(L_DBG, "Initializing LDAP connection pool\n");
    $_CONNECTION_POOL = ResourcePool->new(
        $conn_factory,
        Max        => $max_connection_pool_size,
        MaxTry     => $max_connection_pool_size,
        PreCreate  => $initial_connection_pool_size,
        RetryDelay => [$connection_retry_delay],
    );
}

sub _get_value {
    my ($config, $option_name, $default_value, $required) = @_;
    if (!defined $required) {
        $required = 1;
    }

    my $value = $config->{$option_name};
    if (!defined $value && defined $default_value) {
        radiusd::radlog(L_INFO, msg_using_default_value('ID Store', $option_name, $default_value));
        $value = $default_value;
    }
    if (defined $value) {
        $value =~ s/^\s+|\s+$//g;
    }
    if ((!defined $value || length($value) == 0) && $required) {
        die "No value specified for ID store configuration option '$option_name'\n";
    }
    return $value;
}

sub _ensure_err {
    my ($bundle, $id) = @_;
    die "ID store error message '$id' not specified\n" unless defined $bundle->{$id};
}

sub get_authy_id {
    my (undef, $user_name) = @_;

    # Open a connection to the LDAP server.
    my $conn = $_CONNECTION_POOL->get();
    if (!defined $conn) {
        die $_ERR->{_ERR_ID_CANNOT_OPEN_CONNECTION()}."\n";
    }

    # Retrieve the user's Authy ID.
    radiusd::radlog(L_DBG, "Retrieving Authy ID from LDAP store");
    my $authy_id = eval { _get_authy_id($conn, $user_name) };
    my $error = $@;

    # Free the connection.
    $_CONNECTION_POOL->free($conn);

    die $error if $error;
    return $authy_id;
}

sub _get_authy_id {
    my ($conn, $user_name) = @_;

    # Check that there is a unique entry for the user name.
    my $search_result = eval {
        $conn->search(
            base      => $_USER_BASE_DN,
            sizelimit => 2, # Only two matching entries are needed to detect a clash.
            filter    => "($_USER_NAME_ATTRIBUTE=$user_name)",
            attrs     => [$_ID_ATTRIBUTE],
        );
    };
    my @entries = $search_result->entries();
    if (@entries < 1) {
        radiusd::radlog(L_DBG, "No LDAP user found with $_ID_ATTRIBUTE '$user_name'");
        return undef;
    }
    if (@entries > 1) {
        die sprintf($_ERR->{_ERR_ID_MULTIPLE_USERS_FOUND()}, $_ID_ATTRIBUTE, $user_name);
    }
    radiusd::radlog(L_DBG, "Found user ".($entries[0]->dn()));

    # Check that there is a unique Authy ID in the user details.
    my @authy_ids = $entries[0]->get_value($_ID_ATTRIBUTE);
    if (@authy_ids < 1) {
        radiusd::radlog(L_DBG, "No Authy ID found for LDAP user '$user_name'");
        return undef;
    }
    if (@authy_ids > 1) {
        die sprintf($_ERR->{_ERR_ID_MULTIPLE_IDS_FOUND()}, $user_name)."\n";
    }

    # Return the Authy ID.
    my $authy_id = $authy_ids[0];
    radiusd::radlog(L_DBG, "Found Authy ID '$authy_id' for LDAP user '$user_name'");
    return $authy_id;
}

1;

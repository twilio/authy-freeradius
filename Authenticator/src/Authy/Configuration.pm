package Authy::Configuration;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Authy::ModuleUtil;
use Carp qw(croak);
use Config::IniFiles ();
use File::Spec ();
use HTTP::Status qw(:constants);
use JSON qw(decode_json);
use LWP::UserAgent ();
use Module::Runtime ();
use POSIX;
use Scalar::Util ();

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    cfg_radius_id_param
    cfg_radius_otp_param
    cfg_radius_reply_auth_type
    cfg_radius_state_marker

    cfg_auth_interactive
    cfg_auth_max_attempts
    cfg_auth_otp_enabled
    cfg_auth_one_touch_enabled
    cfg_auth_otp_option
    cfg_auth_one_touch_option
    cfg_auth_id_store_home
    cfg_auth_id_store_module

    cfg_otp_delimiter
    cfg_otp_length
    cfg_otp_always_send_sms
    cfg_otp_allow_unregistered_users

    cfg_one_touch_custom_polling_endpoint_url
    cfg_one_touch_verify_custom_polling_endpoint_hostname
    cfg_one_touch_custom_polling_endpoint_ca_file
    cfg_one_touch_custom_polling_endpoint_ca_path
    cfg_one_touch_polling_interval
    cfg_one_touch_approval_request_timeout
    cfg_one_touch_default_logo_url
    cfg_one_touch_low_res_logo_url
    cfg_one_touch_med_res_logo_url
    cfg_one_touch_high_res_logo_url

    cfg_auth_api_key
    cfg_auth_user_agent
    cfg_auth_silent
    cfg_auth_only_otp_enabled
    cfg_auth_only_one_touch_enabled
    cfg_auth_otp_and_one_touch_enabled
    cfg_auth_id_store_module_path
    cfg_otp_sms_url
    cfg_otp_verification_url
    cfg_one_touch_approval_request_creation_url
    cfg_one_touch_use_custom_polling_endpoint
    cfg_one_touch_polling_endpoint_url

    cfg_id_store
);

our (undef, $_FILE_DIR, undef) = File::Spec->splitpath(__FILE__);
our $_CONFIG_FILE_PATH = File::Spec->join(File::Spec->rel2abs($_FILE_DIR), File::Spec->updir(), 'config.ini');

use constant _PLUGIN_VERSION => '1.0.0';

# Configuration sections:
our $_CFG_RADIUS = {};
our $_CFG_AUTH = {};
our $_CFG_OTP = {};
our $_CFG_ONE_TOUCH = {};
our $_CFG_ID_STORE = {};

# Configuration section names:
use constant {
    _SECTION_RADIUS            => 'RADIUS',
    _SECTION_AUTH              => 'Auth',
    _SECTION_OTP               => 'OTP',
    _SECTION_ONE_TOUCH         => 'OneTouch',
    _SECTION_ID_STORE          => 'ID Store',
};

# RADIUS configuration option names:
use constant {
    _OPT_RADIUS_ID_PARAM        => 'IDParam',
    _OPT_RADIUS_OTP_PARAM       => 'OTPParam',
    _OPT_RADIUS_REPLY_AUTH_TYPE => 'ReplyAuthType',
    _OPT_RADIUS_STATE_MARKER    => 'StateMarker',
};

# Default RADIUS configuration values:
use constant {
    _DEF_RADIUS_ID_PARAM        => 'Authy-ID',
    _DEF_RADIUS_OTP_PARAM       => 'Authy-OTP',
    _DEF_RADIUS_REPLY_AUTH_TYPE => 'authy-reply',
    _DEF_RADIUS_STATE_MARKER    => 'Authy::AuthyState',
};

# Authentication/authorization configuration option names:
use constant {
    _OPT_AUTH_API_KEY_ENV        => 'APIKeyEnv',
    _OPT_AUTH_COMPANY_NAME       => 'CompanyName',
    _OPT_AUTH_INTERACTIVE        => 'Interactive',
    _OPT_AUTH_MAX_ATTEMPTS       => 'MaxAttempts',
    _OPT_AUTH_OTP_ENABLED        => 'OTPEnabled',
    _OPT_AUTH_ONE_TOUCH_ENABLED  => 'OneTouchEnabled',
    _OPT_AUTH_OTP_OPTION         => 'OTPOption',
    _OPT_AUTH_ONE_TOUCH_OPTION   => 'OneTouchOption',
    _OPT_AUTH_ID_STORE_HOME      => 'IDStoreHome',
    _OPT_AUTH_ID_STORE_MODULE    => 'IDStoreModule',
};

# Default authentication/authorization configuration values:
use constant {
    _DEF_AUTH_API_KEY_ENV        => 'AUTHY_API_KEY',
    _DEF_AUTH_COMPANY_NAME       => undef,
    _DEF_AUTH_INTERACTIVE        => 0,
    _DEF_AUTH_MAX_ATTEMPTS       => 1,
    _DEF_AUTH_OTP_ENABLED        => 0,
    _DEF_AUTH_ONE_TOUCH_ENABLED  => 0,
    _DEF_AUTH_OTP_OPTION         => undef,
    _DEF_AUTH_ONE_TOUCH_OPTION   => undef,
    _DEF_AUTH_ID_STORE_HOME      => undef,
    _DEF_AUTH_ID_STORE_MODULE    => undef,
};

# OTP configuration option names:
use constant {
    _OPT_OTP_DELIMITER                => 'Delimiter',
    _OPT_OTP_LENGTH                   => 'Length',
    _OPT_OTP_ALWAYS_SEND_SMS          => 'AlwaysSendSMS',
    _OPT_OTP_ALLOW_UNREGISTERED_USERS => 'AllowUnregisteredUsers',
};

# Default OTP configuration values:
use constant {
    _DEF_OTP_DELIMITER                 => ',',
    _DEF_OTP_LENGTH                    => 7,
    _DEF_OTP_ALWAYS_SEND_SMS           => 0,
    _DEF_OTP_ALLOW_UNREGISTERED_USERS  => 1,
};

# OneTouch configuration option names:
use constant {
    _OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_URL             => 'CustomPollingEndpointURL',
    _OPT_ONE_TOUCH_VERIFY_CUSTOM_POLLING_ENDPOINT_HOSTNAME => 'VerifyCustomPollingEndpointHostname',
    _OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_FILE         => 'CustomPollingEndpointCAFile',
    _OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_PATH         => 'CustomPollingEndpointCAPath',
    _OPT_ONE_TOUCH_POLLING_INTERVAL                        => 'PollingInterval',
    _OPT_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT                => 'ApprovalRequestTimeout',
    _OPT_ONE_TOUCH_DEFAULT_LOGO_URL                        => 'DefaultLogoURL',
    _OPT_ONE_TOUCH_LOW_RES_LOGO_URL                        => 'LowResLogoURL',
    _OPT_ONE_TOUCH_MED_RES_LOGO_URL                        => 'MedResLogoURL',
    _OPT_ONE_TOUCH_HIGH_RES_LOGO_URL                       => 'HighResLogoURL',
};

# Default OneTouch configuration values:
use constant {
    _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_URL             => undef,
    _DEF_ONE_TOUCH_VERIFY_CUSTOM_POLLING_ENDPOINT_HOSTNAME => 1,
    _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_FILE         => undef,
    _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_PATH         => undef,
    _DEF_ONE_TOUCH_POLLING_INTERVAL                        => 0.5,
    _DEF_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT                => 86400,
    _DEF_ONE_TOUCH_DEFAULT_LOGO_URL                        => undef,
    _DEF_ONE_TOUCH_LOW_RES_LOGO_URL                        => undef,
    _DEF_ONE_TOUCH_MED_RES_LOGO_URL                        => undef,
    _DEF_ONE_TOUCH_HIGH_RES_LOGO_URL                       => undef,
};

# URLs:
use constant {
    _AUTHY_API_KEY_VERIFICATION_URL                => 'https://api.authy.com/protected/json/app/details',
    _AUTHY_OTP_SMS_URL                             => 'https://api.authy.com/protected/json/sms/%s?force=%s',
    _AUTHY_OTP_VERIFICATION_URL                    => 'https://api.authy.com/protected/json/verify/%s/%s?force=%s',
    _AUTHY_ONE_TOUCH_APPROVAL_REQUEST_CREATION_URL => 'https://api.authy.com/onetouch/json/users/%s/approval_requests',
    _AUTHY_ONE_TOUCH_POLLING_ENDPOINT              => 'https://api.authy.com/onetouch/json/approval_requests',
};

# Constraints:
use constant {
    _OTP_MIN_LENGTH => 6,
    _OTP_MAX_LENGTH => 8,
};

sub import {
    # Load the configuration if necessary.
    state $loaded_config = 0;
    if (!$loaded_config) {
        _load_config();
        $loaded_config = 1;
    }

    Authy::Configuration->export_to_level(1, @_);
}

sub _load_config {
    # Load the configuration from the configuration file.
    open my $config_fh, '<:encoding(UTF-8)', $_CONFIG_FILE_PATH
        or die "Unable to open configuration file at $_CONFIG_FILE_PATH: $!";
    my $config = Config::IniFiles->new(-file => $config_fh);
    if (!defined $config) {
        my $errors = join '\n', @Config::IniFiles::errors;
        die "Could not load configuration at $_CONFIG_FILE_PATH:\n$errors\n";
    }
    close $config_fh or log_err("Error closing configuration file: $!\n");

    # Extract the RADIUS configuration options.
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_ID_PARAM, _DEF_RADIUS_ID_PARAM);
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_OTP_PARAM, _DEF_RADIUS_OTP_PARAM);
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_REPLY_AUTH_TYPE, _DEF_RADIUS_REPLY_AUTH_TYPE);
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_STATE_MARKER, _DEF_RADIUS_STATE_MARKER);

    # Extract the authentication/authorization configuration options.
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_API_KEY_ENV, _DEF_AUTH_API_KEY_ENV);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_COMPANY_NAME, _DEF_AUTH_COMPANY_NAME);
    _put_bool($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_INTERACTIVE, _DEF_AUTH_INTERACTIVE);
    _put_num ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_MAX_ATTEMPTS, _DEF_AUTH_MAX_ATTEMPTS);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_OTP_ENABLED, _DEF_AUTH_OTP_ENABLED);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ONE_TOUCH_ENABLED, _DEF_AUTH_ONE_TOUCH_ENABLED);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_OTP_OPTION, _DEF_AUTH_OTP_OPTION);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ONE_TOUCH_OPTION, _DEF_AUTH_ONE_TOUCH_OPTION);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ID_STORE_HOME, _DEF_AUTH_ID_STORE_HOME);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ID_STORE_MODULE, _DEF_AUTH_ID_STORE_MODULE);

    # Extract the OTP configuration options.
    _put_str ($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_DELIMITER, _DEF_OTP_DELIMITER);
    _put_num ($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_LENGTH, _DEF_OTP_LENGTH);
    _put_bool($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_ALWAYS_SEND_SMS, _DEF_OTP_ALWAYS_SEND_SMS);
    _put_bool($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_ALLOW_UNREGISTERED_USERS, _DEF_OTP_ALLOW_UNREGISTERED_USERS);

    # Extract the OneTouch configuration options.
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_URL, _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_URL);
    _put_bool($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_VERIFY_CUSTOM_POLLING_ENDPOINT_HOSTNAME, _DEF_ONE_TOUCH_VERIFY_CUSTOM_POLLING_ENDPOINT_HOSTNAME);
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_FILE, _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_FILE);
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_PATH, _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_PATH);
    _put_num ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_POLLING_INTERVAL, _DEF_ONE_TOUCH_POLLING_INTERVAL);
    _put_num ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT, _DEF_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT);
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_DEFAULT_LOGO_URL, _DEF_ONE_TOUCH_DEFAULT_LOGO_URL);
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_LOW_RES_LOGO_URL, _DEF_ONE_TOUCH_LOW_RES_LOGO_URL);
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_MED_RES_LOGO_URL, _DEF_ONE_TOUCH_MED_RES_LOGO_URL);
    _put_str ($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_HIGH_RES_LOGO_URL, _DEF_ONE_TOUCH_HIGH_RES_LOGO_URL);

    # Extract the ID store configuration options.
    _put_section($_CFG_ID_STORE, $config, _SECTION_ID_STORE);

    _validate_options();
}

sub _validate_options {
    # Validate the ID and OTP RADIUS request parameter names.
    die "ID parameter and OTP parameter names must differ\n"
        if lc cfg_radius_id_param() eq lc cfg_radius_otp_param();

    # Verify that the number of max attempts is a positive number.
    die "Max attempt count must be at least 1\n"
        unless cfg_auth_max_attempts() > 0;

    # Verify that at least one authentication method is enabled.
    die "No authentication methods enabled\n"
        unless cfg_auth_otp_enabled() || cfg_auth_one_touch_enabled();

    # Verify that a valid Authy API key is specified.
    die "No API key specified"
        unless defined cfg_auth_api_key();
    die "Invalid API key specified"
        unless _is_valid_api_key(cfg_auth_api_key());

    # Check that a company name is specified, warning otherwise.
    log_info("No company name specified; requests to Authy will not be marked as specific to this company's usage")
        unless defined _cfg_auth_company_name();

    if (cfg_auth_otp_and_one_touch_enabled()) {
        # Verify that both OTP and OneTouch authentication methods have an option value specified.
        die "No OTP authentication option value specified"
            unless defined cfg_auth_otp_option();
        die "No OneTouch authentication option value specified"
            unless defined cfg_auth_one_touch_option();

        # Verify that the OTP and OneTouch options are different.
        die "OTP and OneTouch authentication option values must differ"
            if cfg_auth_otp_option() eq cfg_auth_one_touch_option();
    }

    if (cfg_auth_otp_enabled()) {
        # Verify that a delimiter is specified if necessary (i.e., in silent OTP-only mode).
        die "No OTP delimiter specified"
            if cfg_auth_silent() && cfg_auth_otp_enabled() && !cfg_otp_delimiter();

        # Verify that the OTP length is within range.
        my $otp_length = cfg_otp_length();
        die sprintf("OTP length must be between %s and %s, inclusively", _OTP_MIN_LENGTH, _OTP_MAX_LENGTH)
            if $otp_length < _OTP_MIN_LENGTH || $otp_length > _OTP_MAX_LENGTH;
    }

    if (cfg_auth_one_touch_enabled()) {
        # Verify that the polling interval is positive.
        die "OneTouch approval request status polling interval must be greater than 0"
            unless cfg_one_touch_polling_interval() > 0;

        # Verify that the request timeout is non-negative.
        die "OneTouch approval request timeout must be at least 0"
            unless cfg_one_touch_approval_request_timeout() >= 0;

        # Verify that a default logo URL is specified if a logo of a specific resolution is specified.
        my $specific_res_logo_url = cfg_one_touch_low_res_logo_url()
            // cfg_one_touch_med_res_logo_url()
            // cfg_one_touch_high_res_logo_url();
        die "No default OneTouch approval request logo URL specified"
            if defined $specific_res_logo_url && !defined cfg_one_touch_default_logo_url();
    }

    die sprintf("Invalid ID store module name %s", cfg_auth_id_store_module())
        if defined cfg_auth_id_store_module() && !Module::Runtime::is_module_name(cfg_auth_id_store_module());
}

sub _is_valid_api_key {
    my ($api_key) = @_;

    # Create the web user agent.
    my $user_agent = LWP::UserAgent->new(cookie_jar => {});
    $user_agent->default_header('X-Authy-API-Key' => $api_key);

    # Request the Authy app details using the API key.
    my $res = $user_agent->get(_AUTHY_API_KEY_VERIFICATION_URL);
    my $client_warning = $res->header('Client-Warning');
    if (defined $client_warning && $client_warning eq "Internal response") { # i.e., an internal error
        die sprintf("Could not verify API key: %s\n", $res->decoded_content());
    }

    # Parse the response content.
    my $res_content = $res->decoded_content();
    my $res_json = eval { decode_json($res_content) };
    die sprintf("Could not verify API key: %s\n", $@) if $@;

    # OK => Valid API key.
    # Unauthorized + 60001 => Invalid API key.
    my $res_code = $res->code();
    return 1 if $res_code == HTTP_OK;
    return 0 if $res_code == HTTP_UNAUTHORIZED && $res_json->{error_code} eq '60001';

    # Fail with the Authy-provided error message.
    die sprintf("Could not verify API key: %s\n", $res_json->{message} // $res_content);
}

sub _get_value {
    my ($config, $section_name, $option_name, $default_value) = @_;

    # Extract the option value.
    my $value = $config->val($section_name, $option_name);
    if (!defined $value && defined $default_value) {
        log_info("No value specified for configuration setting '$section_name/$option_name'; ".
                 "using the default value '$default_value'");
        $value = $default_value;
    }
    return undef unless defined $value;

    # Trim the option value.
    $value =~ s/^\s+|\s+$//g;
    return $value ne '' ? $value : undef;
}

sub _put_str {
    my ($dest_config, $src_config, $src_section_name, $option_name, $default_value) = @_;
    $dest_config->{$option_name} = _get_value($src_config, $src_section_name, $option_name, $default_value);
}

sub _put_num {
    my ($dest_config, $src_config, $src_section_name, $option_name, $default_value) = @_;

    # Ensure that the value, if defined, is an integer.
    my $value = _get_value($src_config, $src_section_name, $option_name, $default_value);
    return undef unless defined $value;
    die sprintf(
            "Configuration option '%s/%s' has value '%s' which is not a valid integer",
            $src_section_name, $option_name, $value)
        unless Scalar::Util::looks_like_number($value);

    $dest_config->{$option_name} = $value;
}

sub _put_bool {
    my ($dest_config, $src_config, $src_section_name, $option_name, $default_value) = @_;

    # Ensure that the value, if defined, is a boolean.
    my $value = _get_value($src_config, $src_section_name, $option_name, $default_value);
    return undef unless defined $value;
    if ($value =~ /^(?:true|yes|on|1)$/i) { # "true", "yes", "on", and "1" => true.
        $dest_config->{$option_name} = 1;
    }
    elsif ($value =~ /^(?:false|no|off|0)$/i) { # "false", "no", "off", and "0" => false.
        $dest_config->{$option_name} = 0;
    }
    else {
        die sprintf(
                "Configuration option '%s/%s' has invalid value '%s'; ".
                    "must be 'yes', 'no', 'true', 'false', 'on', 'off', '1', or '0'",
                $src_section_name, $option_name, $value)
    }
}

sub _put_section {
    my ($dest_config, $src_config, $src_section_name) = @_;
    return unless $src_config->SectionExists($src_section_name);
    for my $option_name ($src_config->Parameters($src_section_name)) {
        _put_str($dest_config, $src_config, $src_section_name, $option_name);
    }
}

#
# RADIUS options
#

sub cfg_radius_id_param {
    return $_CFG_RADIUS->{_OPT_RADIUS_ID_PARAM()};
}

sub cfg_radius_otp_param {
    return $_CFG_RADIUS->{_OPT_RADIUS_OTP_PARAM()};
}

sub cfg_radius_reply_auth_type {
    return $_CFG_RADIUS->{_OPT_RADIUS_REPLY_AUTH_TYPE()};
}

sub cfg_radius_state_marker {
    return $_CFG_RADIUS->{_OPT_RADIUS_STATE_MARKER()};
}

#
# Authentication/authorization options
#

sub _cfg_auth_api_key_env {
    return $_CFG_AUTH->{_OPT_AUTH_API_KEY_ENV()};
}

sub _cfg_auth_company_name {
    return $_CFG_AUTH->{_OPT_AUTH_COMPANY_NAME()};
}

sub cfg_auth_interactive {
    return $_CFG_AUTH->{_OPT_AUTH_INTERACTIVE()};
}

sub cfg_auth_max_attempts {
    return $_CFG_AUTH->{_OPT_AUTH_MAX_ATTEMPTS()};
}

sub cfg_auth_otp_enabled {
    return $_CFG_AUTH->{_OPT_AUTH_OTP_ENABLED()};
}

sub cfg_auth_one_touch_enabled {
    return $_CFG_AUTH->{_OPT_AUTH_ONE_TOUCH_ENABLED()};
}

sub cfg_auth_otp_option {
    return $_CFG_AUTH->{_OPT_AUTH_OTP_OPTION()};
}

sub cfg_auth_one_touch_option {
    return $_CFG_AUTH->{_OPT_AUTH_ONE_TOUCH_OPTION()};
}

sub cfg_auth_id_store_home {
    return $_CFG_AUTH->{_OPT_AUTH_ID_STORE_HOME()};
}

sub cfg_auth_id_store_module {
    return $_CFG_AUTH->{_OPT_AUTH_ID_STORE_MODULE()};
}

#
# OTP configuration options
#

sub cfg_otp_delimiter {
    return $_CFG_OTP->{_OPT_OTP_DELIMITER()};
}

sub cfg_otp_length() {
    return $_CFG_OTP->{_OPT_OTP_LENGTH()};
}

sub cfg_otp_always_send_sms {
    return $_CFG_OTP->{_OPT_OTP_ALWAYS_SEND_SMS()};
}

sub cfg_otp_allow_unregistered_users {
    return $_CFG_OTP->{_OPT_OTP_ALLOW_UNREGISTERED_USERS()};
}

#
# OneTouch configuration options
#

sub cfg_one_touch_custom_polling_endpoint_url {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_URL()};
}

sub cfg_one_touch_verify_custom_polling_endpoint_hostname {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_VERIFY_CUSTOM_POLLING_ENDPOINT_HOSTNAME()};
}

sub cfg_one_touch_custom_polling_endpoint_ca_file {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_FILE()};
}

sub cfg_one_touch_custom_polling_endpoint_ca_path {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_PATH()};
}

sub cfg_one_touch_polling_interval {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_POLLING_INTERVAL()};
}

sub cfg_one_touch_approval_request_timeout {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT()};
}

sub cfg_one_touch_default_logo_url {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_DEFAULT_LOGO_URL()};
}

sub cfg_one_touch_low_res_logo_url {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_LOW_RES_LOGO_URL()};
}

sub cfg_one_touch_med_res_logo_url {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_MED_RES_LOGO_URL()};
}

sub cfg_one_touch_high_res_logo_url {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_HIGH_RES_LOGO_URL()};
}

#
# ID store configuration options
#

sub cfg_id_store {
    return $_CFG_ID_STORE;
}

#
# Convenient psuedo-options
#

sub cfg_auth_api_key {
    state $api_key = $ENV{_cfg_auth_api_key_env()};
    return $api_key;
}

sub cfg_auth_user_agent {
    state $user_agent = sprintf(
        "AuthyFreeRADIUS/%s (%s; Perl $^V)%s",
        _PLUGIN_VERSION,
        join(' ', (POSIX::uname())[0, 2, 4]), # <Sysname> <Release> <Machine>
        defined _cfg_auth_company_name() ? ' '._cfg_auth_company_name() : ''
    );
    return $user_agent;
}

sub cfg_auth_silent {
    state $silent = !cfg_auth_interactive();
    return $silent;
}

sub cfg_auth_only_otp_enabled {
    state $enabled = cfg_auth_otp_enabled() && !cfg_auth_one_touch_enabled();
    return $enabled;
}

sub cfg_auth_only_one_touch_enabled {
    state $enabled = cfg_auth_one_touch_enabled() && !cfg_auth_otp_enabled();
    return $enabled;
}

sub cfg_auth_otp_and_one_touch_enabled {
    state $enabled = cfg_auth_one_touch_enabled() && cfg_auth_otp_enabled();
    return $enabled;
}

sub cfg_auth_id_store_module_path {
    state $path;
    return $path if defined $path;

    # Example::Custom::IDStore -> Example/Custom/IDStore.pm
    my @components = split '::', cfg_auth_id_store_module();
    $path = File::Spec->join(@components).'.pm';
    return $path;
}

sub cfg_otp_sms_url {
    my ($id) = @_;
    croak "No ID specified" unless defined $id;
    return sprintf _AUTHY_OTP_SMS_URL, $id, (cfg_otp_always_send_sms() ? 'true' : 'false')
}

sub cfg_otp_verification_url {
    my ($otp, $id) = @_;
    croak "No OTP specified" unless defined $otp;
    croak "No ID specified" unless defined $id;
    return sprintf _AUTHY_OTP_VERIFICATION_URL, $otp, $id, (cfg_otp_allow_unregistered_users() ? 'false' : 'true');
}

sub cfg_one_touch_approval_request_creation_url {
    my ($id) = @_;
    croak "No ID specified" unless defined $id;
    return sprintf _AUTHY_ONE_TOUCH_APPROVAL_REQUEST_CREATION_URL, $id
}

sub cfg_one_touch_use_custom_polling_endpoint {
    state $result = defined cfg_one_touch_custom_polling_endpoint_url();
    return $result;
}

sub cfg_one_touch_polling_endpoint_url {
    my ($request_uuid) = @_;
    croak "No request UUID specified" unless defined $request_uuid;

    # Determine the correct polling endpoint URL root to use.
    my $root = cfg_one_touch_custom_polling_endpoint_url() // _AUTHY_ONE_TOUCH_POLLING_ENDPOINT;

    # Remove the trailing slash, if any.
    if (substr($root, -1) eq '/') {
        $root = substr $root, 0, -1;
    }

    return "$root/$request_uuid";
}

1;

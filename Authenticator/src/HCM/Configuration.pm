package HCM::Configuration;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Carp qw(croak);
use Config::IniFiles ();
use File::Spec ();
use HCM::ModuleUtil;
use HCM::Text;
use HTTP::Status qw(:constants);
use JSON qw(decode_json);
use LWP::UserAgent ();
use Scalar::Util ();

eval "use radiusd"; # For local testing.

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    cfg_radius_id_param
    cfg_radius_otp_param
    cfg_radius_reply_auth_type
    cfg_radius_state_marker

    cfg_auth_production_api_key
    cfg_auth_sandbox_api_key
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
    cfg_otp_use_sandbox_api
    cfg_otp_always_send_sms
    cfg_otp_allow_unregistered_users

    cfg_one_touch_use_sandbox_api
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

    cfg_auth_silent
    cfg_auth_only_otp_enabled
    cfg_auth_only_one_touch_enabled
    cfg_auth_otp_and_one_touch_enabled
    cfg_otp_sms_url
    cfg_otp_verification_url
    cfg_one_touch_approval_request_creation_url
    cfg_one_touch_use_custom_polling_endpoint
    cfg_one_touch_polling_endpoint_url

    cfg_id_store
);

our (undef, $_FILE_DIR, undef) = File::Spec->splitpath(__FILE__);
our $_CONFIG_FILE_PATH = File::Spec->join(File::Spec->rel2abs($_FILE_DIR), File::Spec->updir(), 'config.ini');

# Configuration sections:
our $_CFG_RADIUS = {};
our $_CFG_AUTH = {};
our $_CFG_OTP = {};
our $_CFG_ONE_TOUCH = {};
our $_CFG_ID_STORE = {};

# Configuration section names:
use constant {
    _SECTION_RADIUS    => 'RADIUS',
    _SECTION_AUTH      => 'Auth',
    _SECTION_OTP       => 'OTP',
    _SECTION_ONE_TOUCH => 'OneTouch',
    _SECTION_ID_STORE  => 'ID Store',
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
    _DEF_RADIUS_STATE_MARKER    => 'HCM::AuthyState',
};

# Authentication/authorization configuration option names:
use constant {
    _OPT_AUTH_PRODUCTION_API_KEY_ENV => 'ProductionAPIKeyEnv',
    _OPT_AUTH_SANDBOX_API_KEY_ENV    => 'SandboxAPIKeyEnv',
    _OPT_AUTH_INTERACTIVE            => 'Interactive',
    _OPT_AUTH_MAX_ATTEMPTS           => 'MaxAttempts',
    _OPT_AUTH_OTP_ENABLED            => 'OTPEnabled',
    _OPT_AUTH_ONE_TOUCH_ENABLED      => 'OneTouchEnabled',
    _OPT_AUTH_OTP_OPTION             => 'OTPOption',
    _OPT_AUTH_ONE_TOUCH_OPTION       => 'OneTouchOption',
    _OPT_AUTH_ID_STORE_HOME          => 'IDStoreHome',
    _OPT_AUTH_ID_STORE_MODULE        => 'IDStoreModule',

    _OPT_AUTH_PRODUCTION_API_KEY     => 'ProductionAPIKey',
    _OPT_AUTH_SANDBOX_API_KEY        => 'SandboxAPIKey',
};

# Default authentication/authorization configuration values:
use constant {
    _DEF_AUTH_PRODUCTION_API_KEY_ENV => 'AUTHY_PROD_API_KEY',
    _DEF_AUTH_SANDBOX_API_KEY_ENV    => 'AUTHY_SANDBOX_API_KEY',
    _DEF_AUTH_INTERACTIVE            => 0,
    _DEF_AUTH_MAX_ATTEMPTS           => 1,
    _DEF_AUTH_OTP_ENABLED            => 0,
    _DEF_AUTH_ONE_TOUCH_ENABLED      => 0,
    _DEF_AUTH_OTP_OPTION             => undef,
    _DEF_AUTH_ONE_TOUCH_OPTION       => undef,
    _DEF_AUTH_ID_STORE_HOME          => undef,
    _DEF_AUTH_ID_STORE_MODULE        => undef,

    _DEF_AUTH_PRODUCTION_API_KEY     => undef,
    _DEF_AUTH_SANDBOX_API_KEY        => undef,
};

# OTP configuration option names:
use constant {
    _OPT_OTP_DELIMITER                 => 'Delimiter',
    _OPT_OTP_LENGTH                    => 'Length',
    _OPT_OTP_USE_SANDBOX_API           => 'UseSandboxAPI',
    _OPT_OTP_ALWAYS_SEND_SMS           => 'AlwaysSendSMS',
    _OPT_OTP_ALLOW_UNREGISTERED_USERS  => 'AllowUnregisteredUsers',
};

# Default OTP configuration values:
use constant {
    _DEF_OTP_DELIMITER                 => ',',
    _DEF_OTP_LENGTH                    => 7,
    _DEF_OTP_USE_SANDBOX_API           => 0,
    _DEF_OTP_ALWAYS_SEND_SMS           => 0,
    _DEF_OTP_ALLOW_UNREGISTERED_USERS  => 0,
};

# OneTouch configuration option names:
use constant {
    _OPT_ONE_TOUCH_USE_SANDBOX_API                         => 'UseSandboxAPI',
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
    _DEF_ONE_TOUCH_USE_SANDBOX_API                         => 0,
    _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_URL             => undef,
    _DEF_ONE_TOUCH_VERIFY_CUSTOM_POLLING_ENDPOINT_HOSTNAME => 1,
    _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_FILE         => undef,
    _DEF_ONE_TOUCH_CUSTOM_POLLING_ENDPOINT_CA_PATH         => undef,
    _DEF_ONE_TOUCH_POLLING_INTERVAL                        => 0.5,
    _DEF_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT                => 86400,
    _DEF_ONE_TOUCH_APPROVAL_REQUEST_MESSAGE                => undef,
    _DEF_ONE_TOUCH_DEFAULT_LOGO_URL                        => undef,
    _DEF_ONE_TOUCH_LOW_RES_LOGO_URL                        => undef,
    _DEF_ONE_TOUCH_MED_RES_LOGO_URL                        => undef,
    _DEF_ONE_TOUCH_HIGH_RES_LOGO_URL                       => undef,
};

# URLs:
use constant {
    _AUTHY_OTP_SMS_URL                             => 'https://%s.authy.com/protected/json/sms/%s?force=%s',
    _AUTHY_OTP_VERIFICATION_URL                    => 'https://%s.authy.com/protected/json/verify/%s/%s?force=%s',
    _AUTHY_ONE_TOUCH_APPROVAL_REQUEST_CREATION_URL => 'https://%s.authy.com/onetouch/json/users/%s/approval_requests',
    _AUTHY_ONE_TOUCH_POLLING_ENDPOINT              => 'https://%s.authy.com/onetouch/json/approval_requests',
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

    HCM::Configuration->export_to_level(1, @_);
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
    close $config_fh or warn "Error closing configuration file: $!\n";

    # Extract the RADIUS configuration options.
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_ID_PARAM, _DEF_RADIUS_ID_PARAM);
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_OTP_PARAM, _DEF_RADIUS_OTP_PARAM);
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_REPLY_AUTH_TYPE, _DEF_RADIUS_REPLY_AUTH_TYPE);
    _put_str ($_CFG_RADIUS, $config, _SECTION_RADIUS, _OPT_RADIUS_STATE_MARKER, _DEF_RADIUS_STATE_MARKER);

    # Extract the authentication/authorization configuration options.
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_PRODUCTION_API_KEY_ENV, _DEF_AUTH_PRODUCTION_API_KEY_ENV);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_SANDBOX_API_KEY_ENV, _DEF_AUTH_SANDBOX_API_KEY_ENV);
    _put_bool($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_INTERACTIVE, _DEF_AUTH_INTERACTIVE);
    _put_num ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_MAX_ATTEMPTS, _DEF_AUTH_MAX_ATTEMPTS);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_OTP_ENABLED, _DEF_AUTH_OTP_ENABLED);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ONE_TOUCH_ENABLED, _DEF_AUTH_ONE_TOUCH_ENABLED);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_OTP_OPTION, _DEF_AUTH_OTP_OPTION);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ONE_TOUCH_OPTION, _DEF_AUTH_ONE_TOUCH_OPTION);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ID_STORE_HOME, _DEF_AUTH_ID_STORE_HOME);
    _put_str ($_CFG_AUTH, $config, _SECTION_AUTH, _OPT_AUTH_ID_STORE_MODULE, _DEF_AUTH_ID_STORE_MODULE);

    _put_env ($_CFG_AUTH, _cfg_auth_production_api_key_env(), _OPT_AUTH_PRODUCTION_API_KEY, _DEF_AUTH_PRODUCTION_API_KEY);
    _put_env ($_CFG_AUTH, _cfg_auth_sandbox_api_key_env(), _OPT_AUTH_SANDBOX_API_KEY, _DEF_AUTH_SANDBOX_API_KEY);

    # Extract the OTP configuration options.
    _put_str ($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_DELIMITER, _DEF_OTP_DELIMITER);
    _put_num ($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_LENGTH, _DEF_OTP_LENGTH);
    _put_bool($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_USE_SANDBOX_API, _DEF_OTP_USE_SANDBOX_API);
    _put_bool($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_ALWAYS_SEND_SMS, _DEF_OTP_ALWAYS_SEND_SMS);
    _put_bool($_CFG_OTP, $config, _SECTION_OTP, _OPT_OTP_ALLOW_UNREGISTERED_USERS, _DEF_OTP_ALLOW_UNREGISTERED_USERS);

    # Extract the OneTouch configuration options.
    _put_bool($_CFG_ONE_TOUCH, $config, _SECTION_ONE_TOUCH, _OPT_ONE_TOUCH_USE_SANDBOX_API, _DEF_ONE_TOUCH_USE_SANDBOX_API);
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
    die err_id_and_otp_params_conflict() if lc cfg_radius_id_param() eq lc cfg_radius_otp_param();

    # Verify that the number of max attempts is a positive number.
    die err_invalid_max_attempt_count() unless cfg_auth_max_attempts() > 0;

    # Verify that at least one authentication method is enabled.
    die err_no_authn_methods() unless cfg_auth_otp_enabled() || cfg_auth_one_touch_enabled();

    # Verify that the necessary Authy API keys are specified.
    if ((cfg_auth_otp_enabled() && !cfg_otp_use_sandbox_api())
        || (cfg_auth_one_touch_enabled() && !cfg_one_touch_use_sandbox_api())) {
        die err_no_production_api_key() unless defined cfg_auth_production_api_key();
        #die err_invalid_production_api_key() unless _is_valid_api_key(cfg_auth_production_api_key());
    }
    if ((cfg_auth_otp_enabled() && cfg_otp_use_sandbox_api())
        || (cfg_auth_one_touch_enabled() && cfg_one_touch_use_sandbox_api())) {
        die err_no_sandbox_api_key() unless defined cfg_auth_sandbox_api_key();
        #die err_invalid_sandbox_api_key() unless _is_valid_api_key(cfg_auth_sandbox_api_key(), sandbox => 1);
    }

    if (cfg_auth_otp_and_one_touch_enabled()) {
        # Verify that both OTP and OneTouch authentication methods have an option value specified.
        die err_no_otp_option() unless defined cfg_auth_otp_option();
        die err_no_one_touch_option() unless defined cfg_auth_one_touch_option();

        # Verify that the OTP and OneTouch options are different.
        die err_otp_and_one_touch_options_conflict() if cfg_auth_otp_option() eq cfg_auth_one_touch_option();
    }

    if (cfg_auth_otp_enabled()) {
        # Verify that a delimiter is specified if necessary (i.e., in silent OTP-only mode).
        die err_no_otp_delimiter() if cfg_auth_silent() && cfg_auth_only_otp_enabled() && !cfg_otp_delimiter();

        # Verify that the OTP length is within range.
        my $otp_length = cfg_otp_length();
        die err_invalid_otp_length(_OTP_MIN_LENGTH, _OTP_MAX_LENGTH)
            if $otp_length < _OTP_MIN_LENGTH || $otp_length > _OTP_MAX_LENGTH;
    }

    if (cfg_auth_one_touch_enabled()) {
        # Verify that the polling interval is positive.
        die err_invalid_one_touch_polling_interval() unless cfg_one_touch_polling_interval() > 0;

        # Verify that the request STL is non-negative.
        die err_invalid_one_touch_approval_request_timeout() unless cfg_one_touch_approval_request_timeout() >= 0;

        # Verify that a default logo URL is specified if a logo of a specific resolution is specified.
        my $specific_res_logo_url = cfg_one_touch_low_res_logo_url()
            // cfg_one_touch_med_res_logo_url()
            // cfg_one_touch_high_res_logo_url();
        die err_no_one_touch_default_logo_url()
            if defined $specific_res_logo_url && !defined cfg_one_touch_default_logo_url();
    }
}

sub _is_valid_api_key {
    my $api_key = shift;
    my %options = (
        sandbox => 0,
        @_
    );
    my $err_api_key_verification_failed = $options{sandbox}
        ? \&err_sandbox_api_key_verification_failed
        : \&err_production_api_key_verification_failed;
    my $user_agent = LWP::UserAgent->new(cookie_jar => {});
    $user_agent->default_header('X-Authy-API-Key' => $api_key);

    # Request the Authy app details using the API key.
    my $api_domain = $options{sandbox} ? 'sandbox-api' : 'api';
    my $res = $user_agent->get("https://$api_domain.authy.com/protected/json/app/details");
    my $client_warning = $res->header('Client-Warning');
    if (defined $client_warning && $client_warning eq "Internal response") { # i.e., an internal error
        die $err_api_key_verification_failed->($res->decoded_content())."\n";
    }

    # Parse the response content.
    my $res_content = $res->decoded_content();
    my $res_json = eval { decode_json($res_content) };
    die err_invalid_production_api_key_verification_response($@)."\n" if $@;

    # OK => Valid API key.
    # Unauthorized + 60001 => Invalid API key.
    my $res_code = $res->code();
    return 1 if $res_code == HTTP_OK;
    return 0 if $res_code == HTTP_UNAUTHORIZED && $res_json->{error_code} eq '60001';

    # Fail with the Authy-provided error message.
    die $err_api_key_verification_failed->($res_json->{message} // $res_content)."\n";
}

sub _get_value {
    my ($config, $section_name, $option_name, $default_value) = @_;

    # Extract the option value.
    my $value = $config->val($section_name, $option_name);
    if (!defined $value && defined $default_value) {
        radiusd::radlog(L_INFO, msg_using_default_value($section_name, $option_name, $default_value));
        $value = $default_value;
    }
    return undef unless $value;

    # Trim the option value.
    $value =~ s/^\s+|\s+$//g;
    return $value ? $value : undef;
}

# TODO: Add "Using default value" messages.

sub _put_str {
    my ($dest_config, $src_config, $src_section_name, $option_name, $default_value) = @_;
    $dest_config->{$option_name} = _get_value($src_config, $src_section_name, $option_name, $default_value);
}

sub _put_env {
    my ($dest_config, $var_name, $option_name, $default_value) = @_;
    $dest_config->{$option_name} = $ENV{$var_name} // $default_value;
}

sub _put_num {
    my ($dest_config, $src_config, $src_section_name, $option_name, $default_value) = @_;

    # Ensure that the value, if defined, is an integer.
    my $value = _get_value($src_config, $src_section_name, $option_name, $default_value);
    return undef unless defined $value;
    die err_invalid_config_int($src_section_name, $option_name, $value) unless Scalar::Util::looks_like_number($value);

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
        die err_invalid_config_bool($src_section_name, $option_name, $value);
    }
}

sub _put_section {
    my ($dest_config, $src_config, $section_name) = @_;
    return unless $src_config->SectionExists($section_name);
    for my $param ($src_config->Parameters($section_name)) {
        $dest_config->{$param} = $src_config->val($section_name, $param);
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

sub cfg_auth_interactive {
    return $_CFG_AUTH->{_OPT_AUTH_INTERACTIVE()};
}

sub cfg_auth_production_api_key {
    return $_CFG_AUTH->{_OPT_AUTH_PRODUCTION_API_KEY()};
}

sub cfg_auth_sandbox_api_key {
    return $_CFG_AUTH->{_OPT_AUTH_SANDBOX_API_KEY()};
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

sub _cfg_auth_production_api_key_env {
    return $_CFG_AUTH->{_OPT_AUTH_PRODUCTION_API_KEY_ENV()};
}

sub _cfg_auth_sandbox_api_key_env {
    return $_CFG_AUTH->{_OPT_AUTH_SANDBOX_API_KEY_ENV()};
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

sub cfg_otp_use_sandbox_api {
    return $_CFG_OTP->{_OPT_OTP_USE_SANDBOX_API()};
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

sub cfg_one_touch_use_sandbox_api {
    return $_CFG_ONE_TOUCH->{_OPT_ONE_TOUCH_USE_SANDBOX_API()};
}

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

sub cfg_api_key {
    my %options = (
        sandbox => 0,
        @_
    );
    return $options{sandbox} ? cfg_auth_sandbox_api_key() : cfg_auth_production_api_key();
}

sub cfg_auth_silent {
    return !cfg_auth_interactive();
}

sub cfg_auth_only_otp_enabled {
    return cfg_auth_otp_enabled() && !cfg_auth_one_touch_enabled();
}

sub cfg_auth_only_one_touch_enabled {
    return cfg_auth_one_touch_enabled() && !cfg_auth_otp_enabled();
}

sub cfg_auth_otp_and_one_touch_enabled {
    return cfg_auth_one_touch_enabled() && cfg_auth_otp_enabled();
}

sub cfg_otp_sms_url {
    my ($id) = @_;
    croak "No ID specified" unless defined $id;
    return sprintf _AUTHY_OTP_SMS_URL,
        (cfg_otp_use_sandbox_api() ? 'sandbox-api' : 'api'),
        $id,
        (cfg_otp_always_send_sms() ? 'true' : 'false')
}

sub cfg_otp_verification_url {
    my ($otp, $id) = @_;
    croak "No OTP specified" unless defined $otp;
    croak "No ID specified" unless defined $id;
    return sprintf _AUTHY_OTP_VERIFICATION_URL,
        (cfg_otp_use_sandbox_api() ? 'sandbox-api' : 'api'),
        $otp,
        $id,
        (cfg_otp_allow_unregistered_users() ? 'false' : 'true');
}

sub cfg_one_touch_approval_request_creation_url {
    my ($id) = @_;
    croak "No ID specified" unless defined $id;
    return sprintf _AUTHY_ONE_TOUCH_APPROVAL_REQUEST_CREATION_URL,
        (cfg_one_touch_use_sandbox_api() ? 'sandbox-api' : 'api'),
        $id
}

sub cfg_one_touch_use_custom_polling_endpoint {
    return defined cfg_one_touch_custom_polling_endpoint_url();
}

sub cfg_one_touch_polling_endpoint_url {
    my ($request_uuid) = @_;
    croak "No request UUID specified" unless defined $request_uuid;

    # Determine the correct polling endpoint URL root to use.
    my $root = cfg_one_touch_custom_polling_endpoint_url()
        //  sprintf _AUTHY_ONE_TOUCH_POLLING_ENDPOINT, (cfg_one_touch_use_sandbox_api() ? 'sandbox-api' : 'api');

    # Remove the trailing slash, if any.
    if (substr($root, -1) eq '/') {
        $root = substr $root, 0, -1;
    }

    return "$root/$request_uuid";
}

1;

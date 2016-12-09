package HCM::Text;

use 5.010;
use strict;
use warnings FATAL => 'all';
use feature qw(state);

use Carp qw(croak);
use Config::IniFiles ();
use File::Spec ();

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    msg_using_default_value

    msg_splitting_password
    msg_updating_auth_type_to_reply

    msg_asking_for_authn_method
    msg_unexpected_authy_response

    msg_verifying_otp
    msg_asking_for_otp
    msg_otp_accepted
    msg_otp_rejected

    msg_one_touch_prompt
    msg_polling_one_touch_endpoint
    msg_one_touch_approved
    msg_one_touch_denied
    msg_one_touch_expired

    msg_retrieving_id

    msg_enter_authn_method
    msg_reenter_authn_method
    msg_enter_authn_method_after_otp
    msg_enter_authn_method_after_one_touch
    msg_enter_otp
    msg_reenter_otp
    msg_authn_succeeded
    msg_authn_failed

    msg_id_store

    err_invalid_config_int
    err_invalid_config_bool
    err_id_and_otp_params_conflict
    err_no_production_api_key
    err_no_sandbox_api_key
    err_invalid_production_api_key_verification_response
    err_invalid_sandbox_api_key_verification_response
    err_production_api_key_verification_failed
    err_sandbox_api_key_verification_failed
    err_invalid_production_api_key
    err_invalid_sandbox_api_key
    err_invalid_max_attempt_count
    err_no_authn_methods
    err_no_otp_option
    err_no_one_touch_option
    err_otp_and_one_touch_options_conflict
    err_no_otp_delimiter
    err_invalid_otp_length
    err_invalid_one_touch_polling_interval
    err_invalid_one_touch_approval_request_timeout
    err_no_one_touch_default_logo_url

    err_invalid_state

    err_unexpected_otp_param
    err_no_user_name_in_request
    err_no_password_in_request
    err_no_id_in_request
    err_no_otp_in_request
    err_no_challenge_response_in_request
    err_id_retrieval_failed
    err_invalid_id
    err_no_id_found_for_user

    err_invalid_otp
    err_otp_request_failed
    err_invalid_otp_response
    err_otp_verification_request_failed
    err_invalid_otp_verification_response

    err_one_touch_approval_request_creation_failed
    err_invalid_one_touch_approval_request_creation_response
    err_one_touch_endpoint_polling_failed
    err_invalid_one_touch_endpoint_response
    err_invalid_one_touch_approval_request_status
    err_no_one_touch_approval_request_status

    err_id_store_script_load_failed
    err_invalid_id_store_script

    err_id_store
);

our (undef, $_FILE_DIR, undef) = File::Spec->splitpath(__FILE__);
our $_MESSAGES_FILE_PATH = File::Spec->join(File::Spec->rel2abs($_FILE_DIR), File::Spec->updir(), 'messages.ini');
our $_ERRORS_FILE_PATH = File::Spec->join(File::Spec->rel2abs($_FILE_DIR), File::Spec->updir(), 'errors.ini');

# Text sections:
our $_MSG_AUTH = {};
our $_MSG_ID_STORE = {};
our $_ERR_AUTH = {};
our $_ERR_ID_STORE = {};

# Text section names:
use constant {
    _SECTION_AUTH     => 'Authenticator',
    _SECTION_ID_STORE => 'ID Store',
};

# Configuration messages:
use constant {
    _MSG_ID_USING_DEFAULT_VALUE => 'UsingDefaultValue',
};

# Authorization messages:
use constant {
    _MSG_ID_SPLITTING_PASSWORD          => 'SplittingPassword',
    _MSG_ID_UPDATING_AUTH_TYPE_TO_REPLY => 'UpdatingAuthTypeToReply',
};

# Authentication messages:
use constant {
    _MSG_ID_ASKING_FOR_AUTHN_METHOD   => 'AskingForAuthnMethod',
    _MSG_ID_UNEXPECTED_AUTHY_RESPONSE => 'UnexpectedAuthyResponse',
};

# OTP messages:
use constant {
    _MSG_ID_VERIFYING_OTP  => 'VerifyingOTP',
    _MSG_ID_ASKING_FOR_OTP => 'AskingForOTP',
    _MSG_ID_OTP_ACCEPTED   => 'OTPAccepted',
    _MSG_ID_OTP_REJECTED   => 'OTPRejected',
};

# OneTouch messages:
use constant {
    _MSG_ID_ONE_TOUCH_PROMPT           => 'OneTouchPrompt',
    _MSG_ID_POLLING_ONE_TOUCH_ENDPOINT => 'PollingOneTouchEndpoint',
    _MSG_ID_ONE_TOUCH_APPROVED         => 'OneTouchApproved',
    _MSG_ID_ONE_TOUCH_DENIED           => 'OneTouchDenied',
    _MSG_ID_ONE_TOUCH_EXPIRED          => 'OneTouchExpired',
};

# ID store messages:
use constant {
    _MSG_ID_RETRIEVING_ID => 'RetrievingID',
};

# Prompt/status messages:
use constant {
    _MSG_ID_ENTER_AUTHN_METHOD                 => 'EnterAuthnMethod',
    _MSG_ID_REENTER_AUTHN_METHOD               => 'ReenterAuthnMethod',
    _MSG_ID_ENTER_AUTHN_METHOD_AFTER_OTP       => 'EnterAuthnMethodAfterOTP',
    _MSG_ID_ENTER_AUTHN_METHOD_AFTER_ONE_TOUCH => 'EnterAuthnMethodAfterOneTouch',
    _MSG_ID_ENTER_OTP                          => 'EnterOTP',
    _MSG_ID_REENTER_OTP                        => 'ReenterOTP',
    _MSG_ID_AUTHN_SUCCEEDED                    => 'AuthnSucceeded',
    _MSG_ID_AUTHN_FAILED                       => 'AuthnFailed',
};

# Configuration errors:
use constant {
    _ERR_ID_INVALID_CONFIG_INT                               => 'InvalidConfigInt',
    _ERR_ID_INVALID_CONFIG_BOOL                              => 'InvalidConfigBool',
    _ERR_ID_ID_AND_OTP_PARAMS_CONFLICT                       => 'IDAndOTPParamsConflict',
    _ERR_ID_NO_PRODUCTION_API_KEY                            => 'NoProductionAPIKey',
    _ERR_ID_NO_SANDBOX_API_KEY                               => 'NoSandboxAPIKey',
    _ERR_ID_INVALID_PRODUCTION_API_KEY_VERIFICATION_RESPONSE => 'InvalidProductionAPIKeyVerificationResponse',
    _ERR_ID_INVALID_SANDBOX_API_KEY_VERIFICATION_RESPONSE    => 'InvalidSandboxAPIKeyVerificationResponse',
    _ERR_ID_PRODUCTION_API_KEY_VERIFICATION_FAILED           => 'ProductionAPIKeyVerificationFailed',
    _ERR_ID_SANDBOX_API_KEY_VERIFICATION_FAILED              => 'SandboxAPIKeyVerificationFailed',
    _ERR_ID_INVALID_PRODUCTION_API_KEY                       => 'InvalidProductionAPIKey',
    _ERR_ID_INVALID_SANDBOX_API_KEY                          => 'InvalidSandboxAPIKey',
    _ERR_ID_INVALID_MAX_ATTEMPT_COUNT                        => 'InvalidMaxAttemptCount',
    _ERR_ID_NO_AUTHN_METHODS                                 => 'NoAuthnMethods',
    _ERR_ID_NO_OTP_OPTION                                    => 'NoOTPOption',
    _ERR_ID_NO_ONE_TOUCH_OPTION                              => 'NoOneTouchOption',
    _ERR_ID_OTP_AND_ONE_TOUCH_OPTIONS_CONFLICT               => 'OTPAndOneTouchOptionsConflict',
    _ERR_ID_NO_OTP_DELIMITER                                 => 'NoOTPDelimiter',
    _ERR_ID_INVALID_OTP_LENGTH                               => 'InvalidOTPLength',
    _ERR_ID_INVALID_ONE_TOUCH_POLLING_INTERVAL               => 'InvalidOneTouchPollingInterval',
    _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT       => 'InvalidOneTouchApprovalRequestTimeout',
    _ERR_ID_NO_ONE_TOUCH_DEFAULT_LOGO_URL                    => 'NoOneTouchDefaultLogoURL',
};

# State errors:
use constant {
    _ERR_ID_INVALID_STATE => 'InvalidState',
};

# Authorization errors:
use constant {
    _ERR_ID_UNEXPECTED_OTP_PARAM             => 'UnexpectedOTPParam',
    _ERR_ID_NO_USER_NAME_IN_REQUEST          => 'NoUserNameInRequest',
    _ERR_ID_NO_PASSWORD_IN_REQUEST           => 'NoPasswordInRequest',
    _ERR_ID_NO_ID_IN_REQUEST                 => 'NoIDInRequest',
    _ERR_ID_NO_OTP_IN_REQUEST                => 'NoOTPInRequest',
    _ERR_ID_NO_CHALLENGE_RESPONSE_IN_REQUEST => 'NoChallengeResponseInRequest',
    _ERR_ID_ID_RETRIEVAL_FAILED              => 'IDRetrievalFailed',
    _ERR_ID_INVALID_ID                       => 'InvalidID',
    _ERR_ID_NO_ID_FOUND_FOR_USER             => 'NoIDFoundForUser',
};

# Authentication errors:
# N/A

# OTP errors:
use constant {
    _ERR_ID_INVALID_OTP                       => 'InvalidOTP',
    _ERR_ID_OTP_REQUEST_FAILED                => 'OTPRequestFailed',
    _ERR_ID_INVALID_OTP_RESPONSE              => 'InvalidOTPResponse',
    _ERR_ID_OTP_VERIFICATION_REQUEST_FAILED   => 'OTPVerificationRequestFailed',
    _ERR_ID_INVALID_OTP_VERIFICATION_RESPONSE => 'InvalidOTPVerificationResponse',
};

# OneTouch errors:
use constant {
    _ERR_ID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED           => 'OneTouchApprovalRequestCreationFailed',
    _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_RESPONSE => 'InvalidOneTouchApprovalRequestCreationResponse',
    _ERR_ID_ONE_TOUCH_ENDPOINT_POLLING_FAILED                    => 'OneTouchEndpointPollingFailed',
    _ERR_ID_INVALID_ONE_TOUCH_ENDPOINT_RESPONSE                  => 'InvalidOneTouchEndpointResponse',
    _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_STATUS            => 'InvalidOneTouchApprovalRequestStatus',
    _ERR_ID_NO_ONE_TOUCH_APPROVAL_REQUEST_STATUS                 => 'NoOneTouchApprovalRequestStatus',
};

# ID store errors:
use constant {
    _ERR_ID_ID_STORE_SCRIPT_LOAD_FAILED => 'IDStoreScriptLoadFailed',
    _ERR_ID_INVALID_ID_STORE_SCRIPT     => 'InvalidIDStoreScript',
};

# Configuration error codes:
our %_ERR_CODES = (
    _ERR_ID_INVALID_CONFIG_INT()                                   => '01-001',
    _ERR_ID_INVALID_CONFIG_BOOL()                                  => '01-002',
    _ERR_ID_ID_AND_OTP_PARAMS_CONFLICT()                           => '01-003',
    _ERR_ID_NO_PRODUCTION_API_KEY()                                => '01-004',
    _ERR_ID_NO_SANDBOX_API_KEY()                                   => '01-005',
    _ERR_ID_INVALID_PRODUCTION_API_KEY_VERIFICATION_RESPONSE()     => '01-006',
    _ERR_ID_INVALID_SANDBOX_API_KEY_VERIFICATION_RESPONSE()        => '01-007',
    _ERR_ID_PRODUCTION_API_KEY_VERIFICATION_FAILED()               => '01-008',
    _ERR_ID_SANDBOX_API_KEY_VERIFICATION_FAILED()                  => '01-009',
    _ERR_ID_INVALID_PRODUCTION_API_KEY()                           => '01-010',
    _ERR_ID_INVALID_SANDBOX_API_KEY()                              => '01-011',
    _ERR_ID_INVALID_MAX_ATTEMPT_COUNT()                            => '01-012',
    _ERR_ID_NO_AUTHN_METHODS()                                     => '01-013',
    _ERR_ID_NO_OTP_OPTION()                                        => '01-014',
    _ERR_ID_NO_ONE_TOUCH_OPTION()                                  => '01-015',
    _ERR_ID_OTP_AND_ONE_TOUCH_OPTIONS_CONFLICT()                   => '01-016',
    _ERR_ID_NO_OTP_DELIMITER()                                     => '01-017',
    _ERR_ID_INVALID_OTP_LENGTH()                                   => '01-018',
    _ERR_ID_INVALID_ONE_TOUCH_POLLING_INTERVAL()                   => '01-019',
    _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT()           => '01-020',
    _ERR_ID_NO_ONE_TOUCH_DEFAULT_LOGO_URL()                        => '01-021',

    _ERR_ID_INVALID_STATE()                                        => '02-001',

    _ERR_ID_UNEXPECTED_OTP_PARAM()                                 => '03-001',
    _ERR_ID_NO_USER_NAME_IN_REQUEST()                              => '03-002',
    _ERR_ID_NO_PASSWORD_IN_REQUEST()                               => '03-003',
    _ERR_ID_NO_ID_IN_REQUEST()                                     => '03-004',
    _ERR_ID_NO_OTP_IN_REQUEST()                                    => '03-005',
    _ERR_ID_NO_CHALLENGE_RESPONSE_IN_REQUEST()                     => '03-006',
    _ERR_ID_ID_RETRIEVAL_FAILED()                                  => '03-007',
    _ERR_ID_INVALID_ID()                                           => '03-008',
    _ERR_ID_NO_ID_FOUND_FOR_USER()                                 => '03-009',

    _ERR_ID_INVALID_OTP()                                          => '04-001',
    _ERR_ID_OTP_REQUEST_FAILED()                                   => '04-002',
    _ERR_ID_INVALID_OTP_RESPONSE()                                 => '04-003',
    _ERR_ID_OTP_VERIFICATION_REQUEST_FAILED()                      => '04-004',
    _ERR_ID_INVALID_OTP_VERIFICATION_RESPONSE()                    => '04-005',

    _ERR_ID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED()           => '05-001',
    _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_RESPONSE() => '05-002',
    _ERR_ID_ONE_TOUCH_ENDPOINT_POLLING_FAILED()                    => '05-003',
    _ERR_ID_INVALID_ONE_TOUCH_ENDPOINT_RESPONSE()                  => '05-004',
    _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_STATUS()            => '05-005',
    _ERR_ID_NO_ONE_TOUCH_APPROVAL_REQUEST_STATUS()                 => '05-006',

    _ERR_ID_ID_STORE_SCRIPT_LOAD_FAILED()                          => '06-001',
    _ERR_ID_INVALID_ID_STORE_SCRIPT()                              => '06-002',
);

sub import {
    state $loaded_text = 0;
    if (!$loaded_text) {
        _load_text();
        $loaded_text = 1;
    }

    HCM::Text->export_to_level(1, @_);
}

sub _load_text {
    # Load the message text bundle.
    open my $msg_bundle_fh, '<:encoding(UTF-8)', $_MESSAGES_FILE_PATH
        or die "Unable to open message text bundle at $_MESSAGES_FILE_PATH: $!";
    my $msg_bundle = Config::IniFiles->new(-file => $msg_bundle_fh);
    if (!defined $msg_bundle) {
        my $errors = join '\n', @Config::IniFiles::errors;
        die "Could not load message text bundle at $_MESSAGES_FILE_PATH:\n$errors\n";
    }
    close $msg_bundle_fh;

    # Load the error text bundle.
    open my $err_bundle_fh, '<:encoding(UTF-8)', $_ERRORS_FILE_PATH
        or die "Unable to open error text bundle at $_ERRORS_FILE_PATH: $!";
    my $err_bundle = Config::IniFiles->new(-file => $_ERRORS_FILE_PATH);
    if (!defined $err_bundle) {
        my $errors = join '\n', @Config::IniFiles::errors;
        die "Could not load error text bundle at $_ERRORS_FILE_PATH:\n$errors\n";
    }
    close $err_bundle_fh;

    # Load the confinguration messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_USING_DEFAULT_VALUE);

    # Load the authorization messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_SPLITTING_PASSWORD);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_UPDATING_AUTH_TYPE_TO_REPLY);

    # Load the authentication messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ASKING_FOR_AUTHN_METHOD);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_UNEXPECTED_AUTHY_RESPONSE);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_UNEXPECTED_AUTHY_RESPONSE);

    # Load the OTP messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_VERIFYING_OTP);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ASKING_FOR_OTP);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_OTP_ACCEPTED);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_OTP_REJECTED);

    # Load the OneTouch messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ONE_TOUCH_PROMPT);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_POLLING_ONE_TOUCH_ENDPOINT);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ONE_TOUCH_APPROVED);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ONE_TOUCH_DENIED);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ONE_TOUCH_EXPIRED);

    # Load the ID store messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_RETRIEVING_ID);

    # Load the prompt/status messages.
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ENTER_AUTHN_METHOD);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_REENTER_AUTHN_METHOD);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ENTER_AUTHN_METHOD_AFTER_OTP);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ENTER_AUTHN_METHOD_AFTER_ONE_TOUCH);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_ENTER_OTP);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_REENTER_OTP);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_AUTHN_SUCCEEDED);
    _put_msg($_MSG_AUTH, $msg_bundle, _SECTION_AUTH, _MSG_ID_AUTHN_FAILED);

    # Load the ID store messages.
    _put_section($_MSG_ID_STORE, $msg_bundle, _SECTION_ID_STORE);

    # Load the configuration errors.
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_CONFIG_INT);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_CONFIG_BOOL);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_ID_AND_OTP_PARAMS_CONFLICT);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_PRODUCTION_API_KEY);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_SANDBOX_API_KEY);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_PRODUCTION_API_KEY_VERIFICATION_RESPONSE);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_SANDBOX_API_KEY_VERIFICATION_RESPONSE);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_PRODUCTION_API_KEY_VERIFICATION_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_SANDBOX_API_KEY_VERIFICATION_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_PRODUCTION_API_KEY);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_SANDBOX_API_KEY);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_MAX_ATTEMPT_COUNT);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_AUTHN_METHODS);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_OTP_OPTION);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_ONE_TOUCH_OPTION);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_OTP_AND_ONE_TOUCH_OPTIONS_CONFLICT);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_OTP_DELIMITER);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_OTP_LENGTH);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ONE_TOUCH_POLLING_INTERVAL);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_ONE_TOUCH_DEFAULT_LOGO_URL);

    # Load the state errors.
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_STATE);

    # Load the authorization errors.
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_UNEXPECTED_OTP_PARAM);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_USER_NAME_IN_REQUEST);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_PASSWORD_IN_REQUEST);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_ID_IN_REQUEST);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_OTP_IN_REQUEST);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_CHALLENGE_RESPONSE_IN_REQUEST);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_ID_RETRIEVAL_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ID);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_ID_FOUND_FOR_USER);

    # Load the authentication errors.
    # N/A

    # Load the OTP errors.
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_OTP);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_OTP_REQUEST_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_OTP_RESPONSE);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_OTP_VERIFICATION_REQUEST_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_OTP_VERIFICATION_RESPONSE);

    # Load the OneTouch errors.
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_RESPONSE);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_ONE_TOUCH_ENDPOINT_POLLING_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ONE_TOUCH_ENDPOINT_RESPONSE);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_STATUS);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_NO_ONE_TOUCH_APPROVAL_REQUEST_STATUS);

    # Load the ID store errors.
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_ID_STORE_SCRIPT_LOAD_FAILED);
    _put_err($_ERR_AUTH, $err_bundle, _SECTION_AUTH, _ERR_ID_INVALID_ID_STORE_SCRIPT);
    _put_section($_ERR_ID_STORE, $err_bundle, _SECTION_ID_STORE);
}

sub _get_str {
    my ($bundle, $section_name, $id) = @_;

    # Grab the message from the designated section.
    my $value = $bundle->val($section_name, $id);
    return undef unless defined $value;

    # Trim the option value.
    $value =~ s/^\s+|\s+$//g;
    return $value ? $value : undef;
}

sub _put_msg {
    my ($dest_bundle, $src_bundle, $section_name, $id) = @_;

    my $msg = _get_str($src_bundle, $section_name, $id);
    croak "Message '$id' not found in $_MESSAGES_FILE_PATH" unless defined $msg;
    $dest_bundle->{$id} = $msg;
}

sub _put_err {
    my ($dest_bundle, $src_bundle, $section_name, $id) = @_;

    my $err = _get_str($src_bundle, $section_name, $id);
    croak "Error '$id' not found in $_ERRORS_FILE_PATH" unless defined $err;
    $dest_bundle->{$id} = "Authy-$_ERR_CODES{$id}: $err";
}

sub _put_section {
    my ($dest_bundle, $src_bundle, $section_name) = @_;
    for my $param ($src_bundle->Parameters($section_name)) {
        $dest_bundle->{$param} = $src_bundle->val($section_name, $param);
    }
}

#
# Configuration messages
#

sub msg_using_default_value {
    my ($section_name, $option_name, $default_value) = @_;
    croak "No section name specified" unless defined $section_name;
    croak "No option name specified" unless defined $option_name;
    croak "No default value specified" unless defined $default_value;
    return sprintf $_MSG_AUTH->{_MSG_ID_USING_DEFAULT_VALUE()}, $section_name, $option_name, $default_value;
}

#
# Authorization messages
#

sub msg_splitting_password {
    my ($delimiter) = @_;
    croak "No delimiter specified" unless defined $delimiter;
    return sprintf $_MSG_AUTH->{_MSG_ID_SPLITTING_PASSWORD()}, $delimiter;
}

sub msg_updating_auth_type_to_reply {
    my ($reply_auth_type) = @_;
    croak "No reply Auth-Type specified" unless defined $reply_auth_type;
    return sprintf $_MSG_AUTH->{_MSG_ID_UPDATING_AUTH_TYPE_TO_REPLY()}, $reply_auth_type;
}

#
# Authentication messages
#

sub msg_asking_for_authn_method {
    return $_MSG_AUTH->{_MSG_ID_ASKING_FOR_AUTHN_METHOD()};
}

sub msg_unexpected_authy_response {
    my ($response_code, $response_data) = @_;
    croak "No response code specified" unless defined $response_code;
    croak "No response data specified" unless defined $response_data;
    return sprintf $_MSG_AUTH->{_MSG_ID_UNEXPECTED_AUTHY_RESPONSE()}, $response_code, $response_data;
}

#
# OTP messages
#

sub msg_verifying_otp {
    return $_MSG_AUTH->{_MSG_ID_VERIFYING_OTP()};
}

sub msg_asking_for_otp {
    return $_MSG_AUTH->{_MSG_ID_ASKING_FOR_OTP()};
}

sub msg_otp_accepted {
    return $_MSG_AUTH->{_MSG_ID_OTP_ACCEPTED()};
}

sub msg_otp_rejected {
    return $_MSG_AUTH->{_MSG_ID_OTP_REJECTED()};
}

#
# OneTouch messages
#

sub msg_one_touch_prompt {
    return $_MSG_AUTH->{_MSG_ID_ONE_TOUCH_PROMPT()};
}

sub msg_polling_one_touch_endpoint {
    return $_MSG_AUTH->{_MSG_ID_POLLING_ONE_TOUCH_ENDPOINT()};
}

sub msg_one_touch_approved {
    return $_MSG_AUTH->{_MSG_ID_ONE_TOUCH_APPROVED()};
}

sub msg_one_touch_denied {
    return $_MSG_AUTH->{_MSG_ID_ONE_TOUCH_DENIED()};
}

sub msg_one_touch_expired {
    return $_MSG_AUTH->{_MSG_ID_ONE_TOUCH_EXPIRED()};
}

#
# ID store messages
#

sub msg_retrieving_id {
    my ($user_name) = @_;
    croak "No user name specified" unless defined $user_name;
    return sprintf $_MSG_AUTH->{_MSG_ID_RETRIEVING_ID()}, $user_name;
}

#
# Prompt messages
#

sub msg_enter_authn_method {
    return $_MSG_AUTH->{_MSG_ID_ENTER_AUTHN_METHOD()};
}

sub msg_reenter_authn_method {
    return sprintf $_MSG_AUTH->{_MSG_ID_REENTER_AUTHN_METHOD()}, msg_enter_authn_method();
}

sub msg_enter_authn_method_after_otp {
    return sprintf $_MSG_AUTH->{_MSG_ID_ENTER_AUTHN_METHOD_AFTER_OTP()}, msg_enter_authn_method();
}

sub msg_enter_authn_method_after_one_touch {
    return sprintf $_MSG_AUTH->{_MSG_ID_ENTER_AUTHN_METHOD_AFTER_ONE_TOUCH()}, msg_enter_authn_method();
}

sub msg_enter_otp {
    return $_MSG_AUTH->{_MSG_ID_ENTER_OTP()};
}

sub msg_reenter_otp {
    return $_MSG_AUTH->{_MSG_ID_REENTER_OTP()};
}

sub msg_authn_succeeded {
    return $_MSG_AUTH->{_MSG_ID_AUTHN_SUCCEEDED()};
}

sub msg_authn_failed {
    return $_MSG_AUTH->{_MSG_ID_AUTHN_FAILED()};
}

#
# ID store messages
#

sub msg_id_store {
    return $_MSG_ID_STORE;
}

#
# Configuration errors
#

sub err_invalid_config_int {
    my ($section_name, $option_name, $value) = @_;
    croak "No section name specified" unless defined $section_name;
    croak "No option name specified" unless defined $option_name;
    croak "No value specified" unless defined $value;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_CONFIG_INT()}, $section_name, $option_name, $value;
}

sub err_invalid_config_bool {
    my ($section_name, $option_name, $value) = @_;
    croak "No section name specified" unless defined $section_name;
    croak "No option name specified" unless defined $option_name;
    croak "No value specified" unless defined $value;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_CONFIG_BOOL()}, $section_name, $option_name, $value;
}

sub err_id_and_otp_params_conflict {
    return $_ERR_AUTH->{_ERR_ID_ID_AND_OTP_PARAMS_CONFLICT()};
}

sub err_no_production_api_key {
    return $_ERR_AUTH->{_ERR_ID_NO_PRODUCTION_API_KEY()};
}

sub err_no_sandbox_api_key {
    return $_ERR_AUTH->{_ERR_ID_NO_SANDBOX_API_KEY()};
}

sub err_invalid_production_api_key_verification_response {
    my ($response) = @_;
    croak "No response specified" unless defined $response;
    return sprintf return $_ERR_AUTH->{_ERR_ID_INVALID_PRODUCTION_API_KEY_VERIFICATION_RESPONSE()}, $response;
}

sub err_invalid_sandbox_api_key_verification_response {
    my ($response) = @_;
    croak "No response specified" unless defined $response;
    return sprintf return $_ERR_AUTH->{_ERR_ID_INVALID_SANDBOX_API_KEY_VERIFICATION_RESPONSE()}, $response;
}

sub err_production_api_key_verification_failed {
    my ($reason) = @_;
    croak "No reason specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_PRODUCTION_API_KEY_VERIFICATION_FAILED()}, $reason;
}

sub err_sandbox_api_key_verification_failed {
    my ($reason) = @_;
    croak "No reason specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_SANDBOX_API_KEY_VERIFICATION_FAILED()}, $reason;
}

sub err_invalid_production_api_key {
    return $_ERR_AUTH->{_ERR_ID_INVALID_PRODUCTION_API_KEY()};
}

sub err_invalid_sandbox_api_key {
    return $_ERR_AUTH->{_ERR_ID_INVALID_SANDBOX_API_KEY()};
}

sub err_invalid_max_attempt_count {
    return $_ERR_AUTH->{_ERR_ID_INVALID_MAX_ATTEMPT_COUNT()};
}

sub err_no_authn_methods {
    return $_ERR_AUTH->{_ERR_ID_NO_AUTHN_METHODS()};
}

sub err_no_otp_option {
    return $_ERR_AUTH->{_ERR_ID_NO_OTP_OPTION()};
}

sub err_no_one_touch_option {
    return $_ERR_AUTH->{_ERR_ID_NO_ONE_TOUCH_OPTION()};
}

sub err_otp_and_one_touch_options_conflict {
    return $_ERR_AUTH->{_ERR_ID_OTP_AND_ONE_TOUCH_OPTIONS_CONFLICT()};
}

sub err_no_otp_delimiter {
    return $_ERR_AUTH->{_ERR_ID_NO_OTP_DELIMITER()};
}

sub err_invalid_otp_length {
    my ($min_length, $max_length) = @_;
    croak "No min length specified" unless defined $min_length;
    croak "No max length specified" unless defined $max_length;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_OTP_LENGTH()}, $min_length, $max_length;
}

sub err_invalid_one_touch_polling_interval {
    return $_ERR_AUTH->{_ERR_ID_INVALID_ONE_TOUCH_POLLING_INTERVAL()};
}

sub err_invalid_one_touch_approval_request_timeout {
    return $_ERR_AUTH->{_ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_TIMEOUT()};
}

sub err_no_one_touch_default_logo_url {
    return $_ERR_AUTH->{_ERR_ID_NO_ONE_TOUCH_DEFAULT_LOGO_URL()};
}

#
# State errors
#

sub err_invalid_state {
    my ($state) = @_;
    croak "No state specified" unless defined $state;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_STATE()}, $state;
}

#
# Authorization errors
#

sub err_unexpected_otp_param {
    return $_ERR_AUTH->{_ERR_ID_UNEXPECTED_OTP_PARAM()};
}

sub err_no_user_name_in_request {
    return $_ERR_AUTH->{_ERR_ID_NO_USER_NAME_IN_REQUEST()};
}

sub err_no_password_in_request {
    return $_ERR_AUTH->{_ERR_ID_NO_PASSWORD_IN_REQUEST()};
}

sub err_no_id_in_request {
    return $_ERR_AUTH->{_ERR_ID_NO_ID_IN_REQUEST()};
}

sub err_no_otp_in_request {
    return $_ERR_AUTH->{_ERR_ID_NO_OTP_IN_REQUEST()};
}

sub err_no_challenge_response_in_request {
    return $_ERR_AUTH->{_ERR_ID_NO_CHALLENGE_RESPONSE_IN_REQUEST()};
}

sub err_id_retrieval_failed {
    my ($reason) = @_;
    croak "No reason specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_ID_RETRIEVAL_FAILED()}, $reason;
}

sub err_invalid_id {
    my ($id) = @_;
    croak "No ID specific" unless defined $id;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_ID()}, $id;
}

sub err_no_id_found_for_user {
    return $_ERR_AUTH->{_ERR_ID_NO_ID_FOUND_FOR_USER()};
}

#
# OTP errors
#

sub err_invalid_otp {
    return $_ERR_AUTH->{_ERR_ID_INVALID_OTP()};
}

sub err_otp_request_failed {
    my ($reason) = @_;
    croak "No reaspon specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_OTP_REQUEST_FAILED()}, $reason;
}

sub err_invalid_otp_response {
    my ($reason) = @_;
    croak "No reaspon specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_OTP_RESPONSE()}, $reason;
}

sub err_otp_verification_request_failed {
    my ($reason) = @_;
    croak "No reaspon specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_OTP_VERIFICATION_REQUEST_FAILED()}, $reason;
}

sub err_invalid_otp_verification_response {
    my ($response_data) = @_;
    croak "No response data specified" unless defined $response_data;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_OTP_VERIFICATION_RESPONSE()}, $response_data;
}

#
# OneTouch errors
#

sub err_one_touch_approval_request_creation_failed {
    my ($reason) = @_;
    croak "No reason specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED()}, $reason;
}

sub err_invalid_one_touch_approval_request_creation_response {
    my ($response_data) = @_;
    croak "No response data specified" unless defined $response_data;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_CREATION_RESPONSE()}, $response_data;
}


sub err_one_touch_endpoint_polling_failed {
    my ($reason) = @_;
    croak "No reason specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_ONE_TOUCH_ENDPOINT_POLLING_FAILED()}, $reason;
}

sub err_invalid_one_touch_endpoint_response {
    my ($response_data) = @_;
    croak "No response data specified" unless defined $response_data;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_ONE_TOUCH_ENDPOINT_RESPONSE()}, $response_data;
}

sub err_invalid_one_touch_approval_request_status {
    my ($status) = @_;
    croak "No status specified" unless defined $status;
    return sprintf $_ERR_AUTH->{_ERR_ID_INVALID_ONE_TOUCH_APPROVAL_REQUEST_STATUS()}, $status;
}

sub err_no_one_touch_approval_request_status {
    return $_ERR_AUTH->{_ERR_ID_NO_ONE_TOUCH_APPROVAL_REQUEST_STATUS()};
}

#
# ID store errors
#

sub err_id_store_script_load_failed {
    my ($reason) = @_;
    croak "No reason specified" unless defined $reason;
    return sprintf $_ERR_AUTH->{_ERR_ID_ID_STORE_SCRIPT_LOAD_FAILED()}, $reason;
}

sub err_invalid_id_store_script {
    return $_ERR_AUTH->{_ERR_ID_INVALID_ID_STORE_SCRIPT()};
}

sub err_id_store {
    return $_ERR_ID_STORE;
}

1;

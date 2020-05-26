package Authy::Text;

use 5.010;
use strict;
use warnings FATAL => 'all';
use feature qw(state);

use Authy::ModuleUtil;
use Carp qw(croak);
use Config::IniFiles ();
use File::Spec ();
use Authy::Configuration;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    MSG_PROMPT_ENTER_METHOD
    MSG_PROMPT_INVALID_METHOD
    MSG_PROMPT_ENTER_OTP
    MSG_PROMPT_INCORRECT_OTP
    MSG_PROMPT_ONE_TOUCH
    MSG_PROMPT_ONE_TOUCH_EXPIRED

    MSG_RESULT_SUCCEEDED
    MSG_RESULT_FAILED
    MSG_RESULT_NO_ID
    MSG_RESULT_ERROR

    ERR_ID_STORE_MODULE_LOAD_FAILED
    ERR_ID_STORE_INVALID_MODULE
    ERR_ID_STORE_INITIALIZATION_FAILED

    ERR_AUTH_NO_USER_NAME_IN_REQUEST
    ERR_AUTH_NO_PASSWORD_IN_REQUEST
    ERR_AUTH_NO_ID_IN_REQUEST
    ERR_AUTH_NO_OTP_IN_REQUEST
    ERR_AUTH_NO_CHALLENGE_RESPONSE_IN_REQUEST
    ERR_AUTH_UNEXPECTED_OTP_IN_REQUEST
    ERR_AUTH_ID_RETRIEVAL_FAILED
    ERR_AUTH_INVALID_ID
    ERR_AUTH_INVALID_STATE
    ERR_AUTH_NO_EMAIL_IN_REQUEST
    ERR_AUTH_NO_CELLPHONE_IN_REQUEST
    ERR_AUTH_NO_COUNTRYCODE_IN_REQUEST
    ERR_AUTH_ID_SAVING_FAILED

    ERR_OTP_PROMPT_REQUEST_FAILED_INTERNALLY
    ERR_OTP_PROMPT_REQUEST_FAILED_EXTERNALLY
    ERR_OTP_VERIFICATION_REQUEST_FAILED_INTERNALLY
    ERR_OTP_VERIFICATION_REQUEST_FAILED_EXTERNALLY

    ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_INTERNALLY
    ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_EXTERNALLY
    ERR_ONE_TOUCH_API_ENDPOINT_FAILED_INTERNALLY
    ERR_ONE_TOUCH_API_ENDPOINT_FAILED_EXTERNALLY
    ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_INTERNALLY
    ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_EXTERNALLY
    ERR_ONE_TOUCH_ENDPOINT_RETURNED_INVALID_STATUS

    ERR_CREATE_USER_REQUEST_FAILED_INTERNALLY
    ERR_CREATE_USER_REQUEST_FAILED_EXTERNALLY

    msg
    err
);

our (undef, $_FILE_DIR, undef) = File::Spec->splitpath(__FILE__);
our $_TEXT_BUNDLE_PATH = File::Spec->join(File::Spec->rel2abs($_FILE_DIR), File::Spec->updir(), 'text.ini');

use constant {
    MSG_PROMPT_ENTER_METHOD      => 'Prompts/EnterMethod',
    MSG_PROMPT_INVALID_METHOD    => 'Prompts/InvalidMethod',
    MSG_PROMPT_ENTER_OTP         => 'Prompts/EnterOTP',
    MSG_PROMPT_INCORRECT_OTP     => 'Prompts/IncorrectOTP',
    MSG_PROMPT_ONE_TOUCH         => 'Prompts/OneTouch',
    MSG_PROMPT_ONE_TOUCH_EXPIRED => 'Prompts/OneTouchExpired',

    MSG_RESULT_SUCCEEDED         => 'Results/Succeeded',
    MSG_RESULT_FAILED            => 'Results/Failed',
    MSG_RESULT_NO_ID             => 'Results/NoID',
    MSG_RESULT_ERROR             => 'Results/Error',
};

use constant {
    ERR_ID_STORE_MODULE_LOAD_FAILED                           => '00-001',
    ERR_ID_STORE_INVALID_MODULE                               => '00-002',
    ERR_ID_STORE_INITIALIZATION_FAILED                        => '00-003',

    ERR_AUTH_NO_USER_NAME_IN_REQUEST                          => '01-001',
    ERR_AUTH_NO_PASSWORD_IN_REQUEST                           => '01-002',
    ERR_AUTH_NO_ID_IN_REQUEST                                 => '01-003',
    ERR_AUTH_NO_OTP_IN_REQUEST                                => '01-004',
    ERR_AUTH_NO_CHALLENGE_RESPONSE_IN_REQUEST                 => '01-005',
    ERR_AUTH_UNEXPECTED_OTP_IN_REQUEST                        => '01-006',
    ERR_AUTH_ID_RETRIEVAL_FAILED                              => '01-007',
    ERR_AUTH_INVALID_ID                                       => '01-008',
    ERR_AUTH_INVALID_STATE                                    => '01-009',
    ERR_AUTH_NO_EMAIL_IN_REQUEST                              => '01-010',
    ERR_AUTH_NO_CELLPHONE_IN_REQUEST                          => '01-011',
    ERR_AUTH_NO_COUNTRYCODE_IN_REQUEST                        => '01-012',
    ERR_AUTH_ID_SAVING_FAILED                                 => '01-013',

    ERR_OTP_PROMPT_REQUEST_FAILED_INTERNALLY                  => '02-001',
    ERR_OTP_PROMPT_REQUEST_FAILED_EXTERNALLY                  => '02-002',
    ERR_OTP_VERIFICATION_REQUEST_FAILED_INTERNALLY            => '02-003',
    ERR_OTP_VERIFICATION_REQUEST_FAILED_EXTERNALLY            => '02-004',

    ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_INTERNALLY => '03-001',
    ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_EXTERNALLY => '03-002',
    ERR_ONE_TOUCH_API_ENDPOINT_FAILED_INTERNALLY              => '03-003',
    ERR_ONE_TOUCH_API_ENDPOINT_FAILED_EXTERNALLY              => '03-004',
    ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_INTERNALLY           => '03-005',
    ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_EXTERNALLY           => '03-006',
    ERR_ONE_TOUCH_ENDPOINT_RETURNED_INVALID_STATUS            => '03-007',

    ERR_CREATE_USER_REQUEST_FAILED_INTERNALLY                 => '04-001',
    ERR_CREATE_USER_REQUEST_FAILED_EXTERNALLY                 => '04-002',
};

our %_MESSAGES = ();

our %_ERRORS = (
    ERR_ID_STORE_MODULE_LOAD_FAILED() =>
        "Could not load the ID store module: %s",
    ERR_ID_STORE_INVALID_MODULE() =>
        "The ID store module is invalid; ".
        "please ensure that the 'initialize(\$\$)' and 'get_authy_id(\$\$)' methods are implemented",
    ERR_ID_STORE_INITIALIZATION_FAILED() =>
        "Could not initialize the ID store: %s",

    ERR_AUTH_NO_USER_NAME_IN_REQUEST() =>
        "No user name found in the request",
    ERR_AUTH_NO_PASSWORD_IN_REQUEST() =>
        "No password found in the request",
    ERR_AUTH_NO_ID_IN_REQUEST() =>
        "No Authy ID found in the request",
    ERR_AUTH_NO_OTP_IN_REQUEST() =>
        "No OTP found in the request",
    ERR_AUTH_NO_CHALLENGE_RESPONSE_IN_REQUEST() =>
        "No challenge response in request",
    ERR_AUTH_UNEXPECTED_OTP_IN_REQUEST() =>
        "Request contains an OTP parameter prematurely",
    ERR_AUTH_ID_RETRIEVAL_FAILED() =>
        "ID retrieval failed: %s",
    ERR_AUTH_INVALID_ID() =>
        "Invalid Authy ID",
    ERR_AUTH_INVALID_STATE() =>
        "Invalid Authy state: %s",
    ERR_AUTH_NO_EMAIL_IN_REQUEST() =>
        "No email found in the request",
    ERR_AUTH_NO_CELLPHONE_IN_REQUEST() =>
        "No cellphone found in the request",
    ERR_AUTH_NO_COUNTRYCODE_IN_REQUEST() =>
        "No country code found in the request",
    ERR_AUTH_ID_SAVING_FAILED() =>
        "ID saving failed: %s",

    ERR_OTP_PROMPT_REQUEST_FAILED_INTERNALLY() =>
        "Could not send Authy OTP prompt request: %s",
    ERR_OTP_PROMPT_REQUEST_FAILED_EXTERNALLY() =>
        "Authy OTP prompt request failed with status code %s: %s",
    ERR_OTP_VERIFICATION_REQUEST_FAILED_INTERNALLY() =>
        "Could not send Authy OTP verification request: %s",
    ERR_OTP_VERIFICATION_REQUEST_FAILED_EXTERNALLY() =>
        "Authy OTP verification request failed with status code %s: %s",

    ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_INTERNALLY() =>
        "Authy OneTouch approval request creation failed: %s",
    ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_EXTERNALLY() =>
        "Authy OneTouch approval request creation failed with error code %s: %s",
    ERR_ONE_TOUCH_API_ENDPOINT_FAILED_INTERNALLY() =>
        "Could not poll Authy OneTouch API endpoint: %s",
    ERR_ONE_TOUCH_API_ENDPOINT_FAILED_EXTERNALLY() =>
        "Authy OneTouch API endpoint poll failed with status code %s: %s",
    ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_INTERNALLY() =>
        "Could not poll Authy OneTouch custom endpoint: %s",
    ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_EXTERNALLY() =>
        "Authy OneTouch custom endpoint poll failed with status code %s: %s",
    ERR_ONE_TOUCH_ENDPOINT_RETURNED_INVALID_STATUS() =>
        "Authy OneTouch custom endpoint returned an invalid status: '%s'",

    ERR_CREATE_USER_REQUEST_FAILED_INTERNALLY() =>
        "Could not send Authy create user request: %s",
    ERR_CREATE_USER_REQUEST_FAILED_EXTERNALLY() =>
        "Authy create user request failed with status code %s: %s",
);

sub import {
    state $loaded_text = 0;
    if (!$loaded_text) {
        _load_text();
        $loaded_text = 1;
    }

    Authy::Text->export_to_level(1, @_);
}


sub msg {
    my ($id, @args) = @_;

    my $format = $_MESSAGES{$id};
    croak "No message found for ID '$id'" unless defined $format;
    return sprintf($format, @args);
}

sub err {
    my ($code, @args) = @_;

    say "Code = $code, Args = [@args]";
    my $format = $_ERRORS{$code};
    croak "No error found for code '$code'" unless defined $format;
    return sprintf("AA-$code: $format", @args);
}

sub _load_text {
    # Load the message text bundle.
    open my $text_bundle_fh, '<:encoding(UTF-8)', $_TEXT_BUNDLE_PATH
        or die "Unable to open text bundle at $_TEXT_BUNDLE_PATH: $!";
    my $text_bundle = Config::IniFiles->new(-file => $text_bundle_fh);
    if (!defined $text_bundle) {
        my $errors = join '\n', @Config::IniFiles::errors;
        die "Could not load text bundle at $_TEXT_BUNDLE_PATH:\n$errors\n";
    }
    close $text_bundle_fh or log_err("Error closing text bundle: $!\n");

    _put_msg($text_bundle, MSG_PROMPT_ENTER_METHOD);
    _put_msg($text_bundle, MSG_PROMPT_INVALID_METHOD);
    _put_msg($text_bundle, MSG_PROMPT_ENTER_OTP);
    _put_msg($text_bundle, MSG_PROMPT_INCORRECT_OTP);
    _put_msg($text_bundle, MSG_PROMPT_ONE_TOUCH);
    _put_msg($text_bundle, MSG_PROMPT_ONE_TOUCH_EXPIRED);

    _put_msg($text_bundle, MSG_RESULT_SUCCEEDED);
    _put_msg($text_bundle, MSG_RESULT_FAILED);
    _put_msg($text_bundle, MSG_RESULT_NO_ID);
    _put_msg($text_bundle, MSG_RESULT_ERROR);

    _validate_text();
}

sub _validate_text {
    my $has_multiple_attempts = cfg_auth_max_attempts() > 1;
    if (cfg_auth_otp_and_one_touch_enabled()) {
        _ensure_msg(MSG_PROMPT_ENTER_METHOD);
        _ensure_msg(MSG_PROMPT_INVALID_METHOD) if $has_multiple_attempts;
    }
    if (cfg_auth_otp_enabled()) {
        _ensure_msg(MSG_PROMPT_ENTER_OTP);
        _ensure_msg(MSG_PROMPT_INCORRECT_OTP) if $has_multiple_attempts;
    }
    if (cfg_auth_one_touch_enabled()) {
        _ensure_msg(MSG_PROMPT_ONE_TOUCH);
        _ensure_msg(MSG_PROMPT_ONE_TOUCH_EXPIRED) if $has_multiple_attempts;
    }

    _ensure_msg(MSG_RESULT_SUCCEEDED);
    _ensure_msg(MSG_RESULT_FAILED);
    _ensure_msg(MSG_RESULT_NO_ID);
    _ensure_msg(MSG_RESULT_ERROR);
}

sub _ensure_msg {
    my ($id) = @_;
    die "Message '$id' not defined" unless defined $_MESSAGES{$id};
}

sub _put_msg {
    my ($bundle, $id) = @_;

    # Grab the message from the designated section.
    my ($section_name, $option_name) = split '/', $id, 2;
    my $value = $bundle->val($section_name, $option_name);
    if (defined $value && length($value) > 0) {
        $_MESSAGES{$id} = $value;
    }
}

1;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Authy::AuthyState;
use Authy::Configuration;
use Authy::ModuleUtil;
use Authy::Text;
use Carp qw(croak);
use HTTP::Headers;
use HTTP::Status qw(:constants);
use JSON;
use LWP::UserAgent;
use Module::Load qw(load);
use Time::HiRes qw(time sleep);

# Include the ID store script.
our $_ID_STORE_MODULE;
BEGIN {
    if (defined cfg_auth_id_store_module()) {
        # Load the ID store module.
        $_ID_STORE_MODULE = cfg_auth_id_store_module();
        if (defined cfg_auth_id_store_home()) {
            push @INC, cfg_auth_id_store_home();
        }
        if (!eval "use $_ID_STORE_MODULE; 1") {
            die err(ERR_ID_STORE_MODULE_LOAD_FAILED, $@);
        }
        die err(ERR_ID_STORE_INVALID_MODULE)
            unless defined $_ID_STORE_MODULE->can('initialize') && defined $_ID_STORE_MODULE->can('get_authy_id');

        # Initialize the ID store module with its configuration.
        eval {
            $_ID_STORE_MODULE->initialize(cfg_id_store());
        };
        die err(ERR_ID_STORE_INITIALIZATION_FAILED, $@) if $@;
    }
}

our (%RAD_REQUEST, %RAD_REPLY, %RAD_CHECK);

# OneTouch responses:
use constant {
    _ONE_TOUCH_APPROVED => 1,
    _ONE_TOUCH_DENIED   => 2,
    _ONE_TOUCH_EXPIRED  => 3,
    _ONE_TOUCH_PENDING  => 4,
};

sub authorize {
    my $result = eval { _authorize() };
    if ($@) {
        log_err($@);
        return _reply_error();
    }
    return $result;
}

sub _authorize {
    return cfg_auth_interactive() ? _authorize_interactive() : _authorize_silent();
}

sub _authorize_interactive {
    # Check the state for the Authy-specific marker.
    my $encoded_state = $RAD_REQUEST{'State'};
    return Authy::AuthyState::is_compatible_encoded_state($encoded_state)
        ? _authorize_interactive_with_state($encoded_state)
        : _authorize_interactive_without_state();
}

sub _authorize_interactive_without_state {
    # Validate the request.
    my $user_name = $RAD_REQUEST{'User-Name'};
    return _reply_invalid(ERR_AUTH_NO_USER_NAME_IN_REQUEST) unless defined $user_name;
    if (defined $_ID_STORE_MODULE) {
        # Retrieve the ID using the user name.
        log_dbg("Retrieving Authy ID for '$user_name'");
        my $id = eval { $_ID_STORE_MODULE->get_authy_id($user_name) };
        return _reply_error(ERR_AUTH_ID_RETRIEVAL_FAILED, $@) if $@;

        # If an ID was found, then insert the ID into the request.
        return _reply_updated(id => $id) if _looks_like_valid_id($id);
        return _reply_no_id() unless defined $id;
        return _reply_error(ERR_AUTH_INVALID_ID);
    }
    else {
        # Ensure that the Authy ID has already been found.
        return _reply_noop() if defined $RAD_REQUEST{cfg_radius_id_param()};
        return _reply_invalid(ERR_AUTH_NO_ID_IN_REQUEST);
    }
}

sub _authorize_interactive_with_state {
    my ($encoded_state) = @_;

    # Validate the state.
    my $state = eval { _decode_state($encoded_state) };
    return _reply_invalid(ERR_AUTH_INVALID_STATE, $@) if $@;
    return _reply_invalid(ERR_AUTH_INVALID_STATE, sprintf("Invalid reply type '%s'", $state->get_reply_type()))
        if ($state->get_reply_type() eq REPLY_TYPE_METHOD_DECISION && !cfg_auth_otp_and_one_touch_enabled())
            || ($state->get_reply_type() eq REPLY_TYPE_OTP && !cfg_auth_otp_enabled());

    # Validate the request.
    if (defined $RAD_REQUEST{'User-Password'}) {
        # This is a challenge response. Set the Auth-Type to the reply Auth-Type.
        my $reply_auth_type = cfg_radius_reply_auth_type();
        log_dbg("Updating Auth-Type to reply Auth-Type '$reply_auth_type'");
        return _reply_updated(auth_type => $reply_auth_type);
    }

    return _reply_invalid(ERR_AUTH_NO_CHALLENGE_RESPONSE_IN_REQUEST);
}

sub _authorize_silent {
    # Validate the request.
    my $user_name = $RAD_REQUEST{'User-Name'};
    return _reply_invalid(ERR_AUTH_NO_USER_NAME_IN_REQUEST) unless defined $user_name;
    if (!defined $_ID_STORE_MODULE) {
        # Ensure that the Authy ID has already been found.
        return defined $RAD_REQUEST{cfg_radius_id_param()}
            ? _reply_noop()
            : _reply_invalid(ERR_AUTH_NO_ID_IN_REQUEST);
    }

    # Retrieve the ID using the user name.
    log_dbg("Retrieving Authy ID for '$user_name'");
    my $id = eval { $_ID_STORE_MODULE->get_authy_id($user_name) };
    return _reply_error(ERR_AUTH_ID_RETRIEVAL_FAILED, $@) if $@;
    return _reply_no_id() unless defined $id;
    return _reply_error(ERR_AUTH_INVALID_ID) unless _looks_like_valid_id($id);

    # Nothing needs to be done for OneTouch-only authentication.
    return _reply_noop() if cfg_auth_only_one_touch_enabled();

    # Verify that there is no OTP parameter already specified, as this would suggest a possible injection.
    return _reply_invalid(ERR_AUTH_UNEXPECTED_OTP_IN_REQUEST) if defined $RAD_REQUEST{cfg_radius_otp_param()};

    # Require a password at this point.
    my $full_password = $RAD_REQUEST{'User-Password'};
    return _reply_invalid(ERR_AUTH_NO_PASSWORD_IN_REQUEST) unless defined $full_password;

    # If the password delimiter is not found, then no further action is required.
    my $delimiter = cfg_otp_delimiter();
    return _reply_ok() if !cfg_auth_only_otp_enabled() || index($full_password, $delimiter) < 0;

    # Attempt to split the password at the OTP delimiter.
    log_dbg("Separating password and OTP at delimiter '$delimiter'");
    my $delimiter_index = rindex($full_password, $delimiter);
    my $password = substr $full_password, 0, $delimiter_index;
    my $otp = substr $full_password, $delimiter_index + length $delimiter;

    # Validate the OTP.
    return _reply_updated(id => $id, password => $password, otp => $otp) if _looks_like_valid_otp($otp);
    return _reply_rejection();
}

sub authenticate {
    my $result = eval { _authenticate() };
    if ($@) {
        log_err($@);
        return _reply_error();
    }
    return $result;
}

sub _authenticate {
    # If authentication is not interactive, go to silent authentication mode.
    return cfg_auth_interactive() ? _authenticate_interactive() : _authenticate_silent();
}

sub _authenticate_interactive {
    # Observe the state.
    my $encoded_state = $RAD_REQUEST{'State'};
    if (!Authy::AuthyState::is_compatible_encoded_state($encoded_state)) {
        # Perform an interactive authentication without a state (i.e. pre-response).
        return _authenticate_interactive_without_state();
    }

    # Validate the state.
    my $state = eval { _decode_state($encoded_state) };
    return _reply_invalid(ERR_AUTH_INVALID_STATE, $@) if $@;

    # Perform an interactive authentication with the state (i.e. post-response).
    return _authenticate_interactive_with_state($state);
}

sub _authenticate_interactive_without_state {
    # Create new state.
    my $state = _create_new_state();

    # If only OTP is enabled, then send an OTP request and prompt the user.
    if (cfg_auth_only_otp_enabled()) {
        return _send_otp_request_and_prompt_for_otp($state);
    }

    # If only OneTouch is enabled, then... authenticate using OneTouch. :)
    if (cfg_auth_only_one_touch_enabled()) {
        return _authenticate_one_touch($state->get_id(), $state);
    }

    # If both are enabled, then ask the user to choose the authentication method.
    return _prompt_for_authn_method($state);
}

sub _authenticate_interactive_with_state {
    my ($state) = @_;

    # Retrieve the user response.
    my $response = $RAD_REQUEST{'User-Password'};

    # If only OTP is enabled, then verify the OTP token resposne.
    if ($state->get_reply_type() eq REPLY_TYPE_OTP) {
        return _authenticate_otp($state->get_id(), $response, $state);
    }
    elsif ($state->get_reply_type() eq REPLY_TYPE_METHOD_DECISION) {
        # Determine the type of authentication.
        if ($response eq cfg_auth_otp_option()) {
            return _send_otp_request_and_prompt_for_otp($state);
        }
        elsif ($response eq cfg_auth_one_touch_option()) {
            return _authenticate_one_touch($state->get_id(), $state);
        }

        # This authentication type is not recognized, so fail the current try.
        $state->fail_try();

        # If any retries are left, then
        return $state->can_retry()
            ? _challenge($state, REPLY_TYPE_METHOD_DECISION,
                sprintf("%s\n\n%s", msg(MSG_PROMPT_INVALID_METHOD), msg(MSG_PROMPT_ENTER_METHOD)))
            : _reply_rejection();
    }

    return _reply_invalid(ERR_AUTH_INVALID_STATE, sprintf("Invalid reply type '%s'", $state->get_reply_type()));
}

sub _authenticate_silent {
    my $id = $RAD_REQUEST{cfg_radius_id_param()};
    my $otp = $RAD_REQUEST{cfg_radius_otp_param()};

    # If an OTP has been extracted, then use OTP authentication. Otherwise, use OneTouch authentication.
    # Note: From the authorization checks, it is safe to assume that if no OTP is specified, then OneTouch is enabled.
    return defined $otp ? _authenticate_otp($id, $otp) : _authenticate_one_touch($id);
}

sub _authenticate_otp {
    my ($authy_id, $otp, $state) = @_;

    # Verify the OTP.
    log_dbg("Verifying OTP");
    my $otp_accepted = eval { _is_correct_otp($authy_id, $otp) };
    return _reply_error($@) if $@;

    # If the OTP was accepted, then the authentication has succeeded.
    return _reply_success() if $otp_accepted;
    # If the authentication is silent, then reject immediately.
    return _reply_rejection() if cfg_auth_silent();

    # Fail the current try.
    $state->fail_try();
    if ($state->can_retry()) {
        # If OneTouch is also enabled, then prompt the user for the desired authentication method.
        # Otherwise, send another OTP request.
        return cfg_auth_one_touch_enabled()
            ? _prompt_for_authn_method($state,
                sprintf("%s\n\n%s", msg(MSG_PROMPT_INCORRECT_OTP), msg(MSG_PROMPT_ENTER_METHOD)))
            : _send_otp_request_and_prompt_for_otp($state,
                sprintf("%s\n\n%s", msg(MSG_PROMPT_INCORRECT_OTP), msg(MSG_PROMPT_ENTER_OTP)));
    } else {
        return _reply_rejection();
    }
}

sub _authenticate_one_touch {
    my ($id, $state) = @_;

    # Create the OneTouch approval request.
    my $request_uuid = eval { _create_one_touch_approval_request($id) };
    if ($@) {
        log_err($@);
        return _reply_error();
    }

    while (1) {
        # Poll the OneTouch endpoint until a status is returned.
        log_dbg("Polling the OneTouch endpoint");
        my $one_touch_response = eval { _poll_one_touch_endpoint($request_uuid) };
        if ($@) {
            log_err($@);
            return _reply_error();
        }

        if ($one_touch_response eq _ONE_TOUCH_APPROVED) {
            # If the request was approved, then the authentication has succeeded.
            return _reply_success();
        }
        elsif ($one_touch_response eq _ONE_TOUCH_DENIED) {
            # If the request was denied, the authentication has failed.
            return _reply_rejection();
        }
        else {
            # The request has expired. This is a failure in silent mode.
            log_dbg("OneTouch approval request expired");
            return _reply_rejection() if cfg_auth_silent();

            # Fail the current try.
            $state->fail_try();
            if ($state->can_retry()) {
                # If OTP is also enabled, then prompt the user for the desired authentication method.
                # Otherwise, another OneTouch request will be sent.
                return _prompt_for_authn_method(_create_new_state(),
                        sprintf("%s\n\n%s", msg(MSG_PROMPT_ONE_TOUCH_EXPIRED), msg(MSG_PROMPT_ENTER_METHOD)))
                    if cfg_auth_otp_enabled();
            }
            else {
                return _reply_rejection();
            }
        }
    }
}

sub _send_otp_request_and_prompt_for_otp {
    my ($state, $message) = @_;

    # Send an OTP request.
    eval {
        _send_otp_request($state->get_id());
    };
    if ($@) {
        log_err($@);
        return _reply_rejection();
    }

    # Prompt the user for the OTP.
    log_dbg("Asking user for OTP");
    return _challenge($state, REPLY_TYPE_OTP, $message // msg(MSG_PROMPT_ENTER_OTP));
}

sub _send_otp_request {
    my ($id) = @_;

    # Create the web user agent.
    my $user_agent = _create_web_user_agent();

    # Send the OTP request.
    my $res = $user_agent->get(cfg_otp_sms_url($id));
    eval {
        _ensure_external_response($res);
    };
    die err(ERR_OTP_PROMPT_REQUEST_FAILED_INTERNALLY, $@)."\n" if $@;

    # Convert the response content to JSON.
    my $res_code = $res->code();
    my $res_content = $res->decoded_content();
    my $res_json = eval { JSON->new->allow_nonref->decode($res_content) };
    die err(ERR_OTP_PROMPT_REQUEST_FAILED_EXTERNALLY, $res_code, $@)."\n" if $@;

    # Process the response.
    if ($res_code == HTTP_OK && $res_json->{success}) {
        # log_dbg($res_json->{message});
        return !$res_json->{ignored}; # <- whether or not the SMS response was honored.
    }

    # Fail with the Authy-provided error message.
    die err(ERR_OTP_PROMPT_REQUEST_FAILED_EXTERNALLY, $res_code, $res_json->{message} // $res_content)."\n";
}

sub _is_correct_otp {
    my ($id, $otp) = @_;

    # Fail immediately if the OTP cannot be invalid.
    return 0 unless _looks_like_valid_otp($otp);

    # Create the web user agent.
    my $user_agent = _create_web_user_agent();

    # Send the OTP verification request.
    my $res = $user_agent->get(cfg_otp_verification_url($otp, $id));
    eval {
        _ensure_external_response($res);
    };
    die err(ERR_OTP_VERIFICATION_REQUEST_FAILED_INTERNALLY, $@)."\n" if $@;

    # Convert the response content to JSON.
    my $res_code = $res->code();
    my $res_content = $res->decoded_content();
    my $res_json = eval { JSON->new->allow_nonref->decode($res_content) };
    die err(ERR_OTP_VERIFICATION_REQUEST_FAILED_EXTERNALLY, $res_code, $@)."\n" if $@;

    # The token is valid if the response was 200 OK and the token "is valid".
    return 1 if $res_code == HTTP_OK && ($res_json->{token} // '') eq 'is valid';

    # The token is invalid if the response was 401 Unauthorized and the token "is invalid".
    return 0 if $res_code == HTTP_UNAUTHORIZED && ($res_json->{token} // '') eq 'is invalid';

    # Fail with the Authy-provided error message.
    die err(ERR_OTP_VERIFICATION_REQUEST_FAILED_EXTERNALLY, $res_code, $res_json->{message} // $res_content)."\n";
}

sub _create_one_touch_approval_request {
    my ($id) = @_;

    # Create the web user agent.
    my $user_agent = _create_web_user_agent();

    # Create the logo data.
    my @logos = ();
    if (cfg_one_touch_default_logo_url()) {
        push @logos, { res => 'default', url => cfg_one_touch_default_logo_url() };
    }
    if (cfg_one_touch_low_res_logo_url()) {
        push @logos, { res => 'low', url => cfg_one_touch_low_res_logo_url() };
    }
    if (cfg_one_touch_med_res_logo_url()) {
        push @logos, { res => 'med', url => cfg_one_touch_med_res_logo_url() };
    }
    if (cfg_one_touch_high_res_logo_url()) {
        push @logos, { res => 'high', url => cfg_one_touch_high_res_logo_url() };
    }

    # Create the OneTouch approval request.
    my $data = {
        message           => msg(MSG_PROMPT_ONE_TOUCH),
        seconds_to_expire => cfg_one_touch_approval_request_timeout(),
        logos             => \@logos,
    };
    my $res = $user_agent->post(cfg_one_touch_approval_request_creation_url($id),
        Content_Type => 'application/json',
        Content => JSON->new->allow_nonref->encode($data)
    );
    eval {
        _ensure_external_response($res);
    };
    die err(ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_INTERNALLY, $@)."\n" if $@;

    # Convert the response content to JSON.
    my $res_code = $res->code();
    my $res_content = $res->decoded_content();
    my $res_json = eval { JSON->new->allow_nonref->decode($res_content) };
    die err(ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_EXTERNALLY, $res_code, $@)."\n" if $@;

    # Return the request UUID sent back from Authy if provided.
    my $request_uuid = $res_json->{approval_request}->{uuid};
    return $request_uuid if $res_code == HTTP_OK && defined $request_uuid;

    # Fail with the Authy-specified error message.
    die err(ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_EXTERNALLY,
            $res_code, $res_json->{message} // $res_content)."\n";
}

sub _poll_one_touch_endpoint {
    my ($request_uuid) = @_;

    # Create the web user agent.
    my $user_agent = cfg_one_touch_use_custom_polling_endpoint()
        ? _create_web_user_agent(
            verify_hostname => cfg_one_touch_verify_custom_polling_endpoint_hostname(),
            ca_file => cfg_one_touch_custom_polling_endpoint_ca_file(),
            ca_path => cfg_one_touch_custom_polling_endpoint_ca_path())
        : _create_web_user_agent();

    # Construct the OneTouch endpoint URL.
    my $endpoint_url = cfg_one_touch_polling_endpoint_url($request_uuid);

    # Poll the endpoint until the request is approved, denied, or expired.
    my $current_time = time();
    my $expiration_time = $current_time + cfg_one_touch_approval_request_timeout(); # Used for the custom endpoint.
    while (!cfg_one_touch_use_custom_polling_endpoint() || $current_time < $expiration_time) {
        # Calculate the time when the next request should be sent.
        my $next_poll_time = $current_time + cfg_one_touch_polling_interval();

        # Retrieve the status of the OneTouch approval request.
        my $status = _retrieve_one_touch_approval_request_status($user_agent, $endpoint_url);
        return $status if $status != _ONE_TOUCH_PENDING;

        # Update the timestamp and sleep for the remainder of the polling interval.
        my $sleep_duration = $next_poll_time - time();
        sleep($sleep_duration) if $sleep_duration > 0;
        $current_time = time();
    }
    return _ONE_TOUCH_EXPIRED;
}

sub _retrieve_one_touch_approval_request_status {
    my ($user_agent, $endpoint_url) = @_;

    # Retrieve the OneTouch approval request status.
    my $res = $user_agent->get($endpoint_url);
    eval {
        _ensure_external_response($res);
    };
    if ($@) {
        # Generate the error message based on the endpoint being used.
        my $reason = $@;
        my $error_code = cfg_one_touch_use_custom_polling_endpoint()
            ? ERR_ONE_TOUCH_API_ENDPOINT_FAILED_INTERNALLY
            : ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_INTERNALLY;
        die (err($error_code, $reason));
    }

    # Poll the correct endpoint.
    return cfg_one_touch_use_custom_polling_endpoint()
        ? _parse_one_touch_custom_endpoint_response($res)
        : _parse_one_touch_api_endpoint_response($res);
}

sub _parse_one_touch_api_endpoint_response {
    my ($res) = @_;

    # Convert the response content to JSON.
    my $res_code = $res->code();
    my $res_content = $res->decoded_content();
    my $res_json = eval { JSON->new->allow_nonref->decode($res_content) };
    die err(ERR_ONE_TOUCH_APPROVAL_REQUEST_CREATION_FAILED_EXTERNALLY, $res_code, $@)."\n" if $@;

    # Extract the response details.
    if ($res_code == HTTP_OK) {
        # Extract the status.
        my $status = $res_json->{approval_request}->{status};
        return _ONE_TOUCH_APPROVED if $status eq 'approved';
        return _ONE_TOUCH_DENIED if $status eq 'denied';
        return _ONE_TOUCH_EXPIRED if $status eq 'expired';
        return _ONE_TOUCH_PENDING if $status eq 'pending';
        die err(ERR_ONE_TOUCH_ENDPOINT_RETURNED_INVALID_STATUS, $status // '')."\n";
    }

    # Fail with the Authy-provided error message.
    die err(ERR_ONE_TOUCH_API_ENDPOINT_FAILED_EXTERNALLY, $res_code, $res_json->{message} // $res_content)."\n";
}

sub _parse_one_touch_custom_endpoint_response {
    my ($res) = @_;

    # Extract the response details.
    my $res_code = $res->code();
    my $res_content = $res->decoded_content();
    if ($res_code == HTTP_OK) {
        # Extract the status.
        return _ONE_TOUCH_APPROVED if $res_content eq 'approved';
        return _ONE_TOUCH_DENIED if $res_content eq 'denied';
        die err(ERR_ONE_TOUCH_ENDPOINT_RETURNED_INVALID_STATUS, $res_content // '')."\n";
    }

    # If no content is returned, then we assume that the request is pending
    # Note: This is under the assumption that the UUID is valid since it was retrieved from Authy.
    return _ONE_TOUCH_PENDING if $res_code == HTTP_NO_CONTENT;

    # Fail with the endpoint response data.
    die err(ERR_ONE_TOUCH_CUSTOM_ENDPOINT_FAILED_EXTERNALLY, $res_code, $res_content)."\n";
}

sub _prompt_for_authn_method {
    my ($state, $message) = @_;
    log_dbg("Asking user for authentication method");
    return _challenge($state, REPLY_TYPE_METHOD_DECISION, $message // msg(MSG_PROMPT_ENTER_METHOD));
}

sub _looks_like_valid_id {
    my ($id) = @_;
    return defined $id && $id =~ /^\d+$/;
}

sub _looks_like_valid_otp {
    my ($otp) = @_;
    return defined $otp && $otp =~ /^\d+$/ && length $otp == cfg_otp_length();
}

sub _create_new_state {
    my ($reply_type) = @_;
    return Authy::AuthyState->new(
        id => $RAD_REQUEST{cfg_radius_id_param()},
        tries_remaining => cfg_auth_max_attempts(),
        reply_type => $reply_type
    );
}

sub _decode_state {
    my ($encoded_state) = @_;
    return defined $encoded_state ? Authy::AuthyState->load($encoded_state // $RAD_REQUEST{'State'}) : undef;
}

sub _save_state {
    my ($state) = @_;
    $RAD_REPLY{'State'} = "$state";
}

sub _challenge {
    my ($state, $reply_type, $message) = @_;

    $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
    $state->set_reply_type($reply_type);
    _save_state($state);
    return _reply(RLM_MODULE_HANDLED, $message);
}

sub _reply_ok {
    return _reply(RLM_MODULE_OK);
}

sub _reply_success {
    return _reply(RLM_MODULE_OK, msg(MSG_RESULT_SUCCEEDED));
}

sub _reply_rejection {
    my ($error_code, @error_args) = @_;
    if (defined $error_code) {
        log_err(err($error_code, @error_args));
    }
    return _reply(RLM_MODULE_REJECT, msg(MSG_RESULT_FAILED));
}

sub _reply_no_id {
    return _reply(RLM_MODULE_REJECT, msg(MSG_RESULT_NO_ID));
}

sub _reply_error {
    my ($error_code, @error_args) = @_;
    if (defined $error_code) {
        log_err(err($error_code, @error_args));
    }
    return _reply(RLM_MODULE_FAIL, msg(MSG_RESULT_ERROR));
}

sub _reply_invalid {
    my ($error_code, @error_args) = @_;
    log_err(err($error_code, @error_args)); # Note: Error code is not optional.
    return _reply(RLM_MODULE_INVALID, msg(MSG_RESULT_ERROR));
}

sub _reply_noop {
    return _reply(RLM_MODULE_NOOP);
}

sub _reply_updated {
    my (%new_values) = @_;

    $RAD_REQUEST{'User-Password'} = $new_values{password} if exists $new_values{password};
    $RAD_REQUEST{cfg_radius_otp_param()} = $new_values{otp} if exists $new_values{otp};
    $RAD_REQUEST{cfg_radius_id_param()} = $new_values{id} if exists $new_values{id};
    $RAD_CHECK{'Auth-Type'} = $new_values{auth_type} if exists $new_values{auth_type};
    return _reply(RLM_MODULE_UPDATED);
}

sub _reply {
    my ($code, $message) = @_;

    if (defined $message) {
        $message = "$message"; # <- in case the message is not a string
        $message =~ s/\s+$//g; # Trim the message.
        $RAD_REPLY{'Reply-Message'} = $message;
    }
    return $code;
}

sub _create_web_user_agent {
    my %options = (
        verify_hostname => 1,
        ca_file         => undef,
        ca_path         => undef,
        @_
    );

    my $user_agent = LWP::UserAgent->new(cookie_jar => {});
    $user_agent->default_header('User-Agent', cfg_auth_user_agent());
    $user_agent->default_header('X-Authy-API-Key' => cfg_auth_api_key());
    $user_agent->ssl_opts(verify_hostname => $options{verify_hostname});
    $user_agent->ssl_opts(SSL_ca_file => $options{ca_file});
    $user_agent->ssl_opts(SSL_ca_path => $options{ca_path});
    return $user_agent;
}

sub _ensure_external_response {
    my ($res) = @_;
    my $res_code = $res->code();
    my $client_warning = $res->header('Client-Warning');
    if ($res_code == 500 && defined $client_warning && $client_warning eq "Internal response") { # i.e., an internal error
        die $res->decoded_content()."\n";
    }
}

sub detach {
    if (defined $_ID_STORE_MODULE && $_ID_STORE_MODULE->can('destroy')) {
        $_ID_STORE_MODULE->destroy();
    }
}

1;

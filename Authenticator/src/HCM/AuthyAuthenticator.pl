use 5.010;
use strict;
use warnings FATAL => 'all';

use Carp qw(croak);
use HCM::AuthyState;
use HCM::Configuration;
use HCM::ModuleUtil;
use HCM::Text;
use HTTP::Headers;
use HTTP::Status qw(:constants);
use JSON qw(encode_json decode_json);
use LWP::UserAgent;
use Module::Load qw(load);
use Time::HiRes qw(time sleep);

eval "use radiusd"; # For local testing.

# Include the ID store script.
our $_ID_STORE_MODULE = cfg_auth_id_store_module();
if (defined $_ID_STORE_MODULE) {
    if (defined cfg_auth_id_store_home()) {
        push @INC, cfg_auth_id_store_home();
    }
    load $_ID_STORE_MODULE;
    die err_invalid_id_store_script()
        unless defined $_ID_STORE_MODULE->can('initialize') && defined $_ID_STORE_MODULE->can('get_authy_id');

    # Initialize the ID store module with its configuration, message bundle, and error bundle.
    eval {
        $_ID_STORE_MODULE->initialize(
            config => cfg_id_store(),
            messages => msg_id_store(),
            errors => err_id_store()
        );
    };
    die "Could not initialize ID store: $@\n" if $@;
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
    return cfg_auth_interactive() ? _authorize_interactive() : _authorize_silent();
}

sub _authorize_interactive {
    # Check the state for the Authy-specific marker.
    my $encoded_state = $RAD_REQUEST{'State'};
    return HCM::AuthyState::is_compatible_encoded_state($encoded_state)
        ? _authorize_interactive_with_state($encoded_state)
        : _authorize_interactive_without_state();
}

sub _authorize_interactive_without_state {
    # Validate the request.
    my $user_name = $RAD_REQUEST{'User-Name'};
    return _reply(RLM_MODULE_INVALID, err_no_user_name_in_request()) unless defined $user_name;
    if (!defined $_ID_STORE_MODULE) {
        return defined $RAD_REQUEST{cfg_radius_id_param()}
            ? _reply(RLM_MODULE_NOOP)
            : _reply(RLM_MODULE_INVALID, err_no_id_in_request());
    }

    # Retrieve the ID using the user name.
    radiusd::radlog(L_DBG, msg_retrieving_id($user_name));
    my $id = eval { $_ID_STORE_MODULE->get_authy_id($user_name) };
    return _reply(RLM_MODULE_FAIL, err_id_retrieval_failed($@)) if $@;
    return _reply(RLM_MODULE_FAIL, err_invalid_id($id)) unless _looks_like_valid_id($id);
    return _reply(RLM_MODULE_REJECT, err_no_id_found_for_user()) unless defined $id;

    # Insert the ID into the request.
    $RAD_REQUEST{cfg_radius_id_param()} = $id;
    return _reply(RLM_MODULE_UPDATED);
}

sub _authorize_interactive_with_state {
    my ($encoded_state) = @_;

    # Validate the state.
    my $state = eval { _decode_state($encoded_state) };
    return _reply(RLM_MODULE_INVALID, $@) if $@;
    return _reply(RLM_MODULE_INVALID, err_invalid_state($encoded_state))
        if ($state->get_reply_type() eq REPLY_TYPE_METHOD_DECISION && !cfg_auth_otp_and_one_touch_enabled())
            || ($state->get_reply_type() eq REPLY_TYPE_OTP && !cfg_auth_otp_enabled());

    # Validate the request.
    my $response = $RAD_REQUEST{'User-Password'};
    return _reply(RLM_MODULE_INVALID, err_no_challenge_response_in_request()) if !defined $response;

    # This is a challenge response. Set the Auth-Type to the reply Auth-Type.
    my $reply_auth_type = cfg_radius_reply_auth_type();
    radiusd::radlog(L_DBG, msg_updating_auth_type_to_reply($reply_auth_type));
    $RAD_CHECK{'Auth-Type'} = $reply_auth_type;
    return _reply(RLM_MODULE_UPDATED);
}

sub _authorize_silent {
    # Validate the request.
    return _reply(RLM_MODULE_INVALID, err_no_id_in_request()) if !defined $RAD_REQUEST{cfg_radius_id_param()};

    # Nothing needs to be done for OneTouch-only authentication.
    return _reply(RLM_MODULE_OK) if cfg_auth_only_one_touch_enabled();

    # Verify that there is no OTP parameter already specified, as this would suggest a possible injection.
    return _reply(RLM_MODULE_INVALID, err_unexpected_otp_param()) if defined $RAD_REQUEST{cfg_radius_otp_param()};

    # Require a password at this point.
    my $full_password = $RAD_REQUEST{'User-Password'};
    return _reply(RLM_MODULE_INVALID, err_no_password_in_request()) if !defined $full_password;

    # If the password delimiter is not found, then no further action is required.
    my $delimiter = cfg_otp_delimiter();
    return RLM_MODULE_OK unless defined $delimiter && index($full_password, $delimiter) != -1;

    # Attempt to split the password at the OTP delimiter.
    radiusd::radlog(L_DBG, msg_splitting_password($delimiter));
    my ($password, $otp) = split($delimiter, $full_password, 2);

    # Validate the OTP.
    return _reply(RLM_MODULE_REJECT, err_invalid_otp()) if $otp !~ /^\d{7}$/;

    # Place the password and OTP into the request.
    $RAD_REQUEST{'User-Password'} = $password;
    $RAD_REQUEST{cfg_radius_otp_param()} = $otp;
    return _reply(RLM_MODULE_UPDATED);
}

sub authenticate {
    # If authentication is not interactive, go to silent authentication mode.
    if (!cfg_auth_interactive()) {
        return _authenticate_silent();
    }

    # Observe the state.
    my $encoded_state = $RAD_REQUEST{'State'};
    if (!HCM::AuthyState::is_compatible_encoded_state($encoded_state)) {
        # Perform an interactive authentication without a state (i.e. pre-response).
        return _authenticate_interactive_without_state();
    }

    # Validate the state.
    my $state = eval { _decode_state($encoded_state) };
    return _reply(RLM_MODULE_INVALID, $@) if $@;

    # Perform an interactive authentication with the state (i.e. post-response).
    return _authenticate_interactive_with_state($state);
}

sub _authenticate_silent {
    my $id = $RAD_REQUEST{cfg_radius_id_param()};
    my $otp = $RAD_REQUEST{cfg_radius_otp_param()};
    return defined $otp ? _authenticate_otp($id, $otp) : _authenticate_one_touch($id);
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
        return _authenticate_one_touch($state->get_id(), _create_new_state());
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

    # Determine the type of authentication.
    if ($response eq cfg_auth_otp_option()) {
        return _send_otp_request_and_prompt_for_otp($state);
    }
    if ($response eq cfg_auth_one_touch_option()) {
        return _authenticate_one_touch($state->get_id(), $state);
    }

    # Fail the current try.
    $state->fail_try();

    # If any retries are left, then
    return $state->can_retry()
        ? _challenge($state, REPLY_TYPE_METHOD_DECISION, msg_reenter_authn_method())
        : _reply(RLM_MODULE_REJECT, msg_authn_failed());
}

sub _authenticate_otp {
    my ($authy_id, $otp, $state) = @_;

    # Verify the OTP.
    radiusd::radlog(L_DBG, msg_verifying_otp());
    my $otp_accepted = eval { _is_correct_otp($authy_id, $otp) };
    return _reply(RLM_MODULE_FAIL, $@) if $@;

    # Log the result.
    radiusd::radlog(L_DBG, $otp_accepted ? msg_otp_accepted() : msg_otp_rejected());

    # If the OTP was accepted, then the authentication has succeeded.
    return _reply(RLM_MODULE_OK, msg_authn_succeeded()) if $otp_accepted;
    # If the authentication is silent, then fail immediately.
    return _reply(RLM_MODULE_REJECT, msg_authn_failed()) if cfg_auth_silent();

    # Fail the current try.
    $state->fail_try();
    return _reply(RLM_MODULE_REJECT, msg_authn_failed()) unless $state->can_retry();

    # If OneTouch is also enabled, then prompt the user for the desired authentication method.
    # Otherwise, send another OTP request.
    return cfg_auth_one_touch_enabled()
        ? _prompt_for_authn_method($state, msg_enter_authn_method_after_otp())
        : _send_otp_request_and_prompt_for_otp($state, msg_reenter_otp());
}

sub _authenticate_one_touch {
    my ($id, $state) = @_;

    # Create the OneTouch approval request.
    my $request_uuid = eval { _create_one_touch_approval_request($id) };
    return _reply(RLM_MODULE_FAIL, $@) if $@;

    while (1) {
        # Poll the OneTouch endpoint until a status is returned.
        radiusd::radlog(L_DBG, msg_polling_one_touch_endpoint());
        my $one_touch_response = eval { _poll_one_touch_endpoint($request_uuid) };
        return _reply(RLM_MODULE_FAIL, $@) if $@;

        # If the request was approved, then the authentication has succeeded.
        if ($one_touch_response eq _ONE_TOUCH_APPROVED) {
            radiusd::radlog(L_DBG, msg_one_touch_approved());
            return _reply(RLM_MODULE_OK, msg_authn_succeeded());
        }
        # If the request was denied, the authentication has failed.
        if ($one_touch_response eq _ONE_TOUCH_DENIED) {
            radiusd::radlog(L_DBG, msg_one_touch_denied());
            return _reply(RLM_MODULE_REJECT, msg_authn_failed())
        }

        # The request has expired. This is a failure in silent mode.
        radiusd::radlog(L_DBG, msg_one_touch_expired());
        if (cfg_auth_silent()) {
            return _reply(RLM_MODULE_REJECT, msg_authn_failed());
        }

        # Fail the current try.
        $state->fail_try();
        return _reply(RLM_MODULE_REJECT, msg_authn_failed()) unless $state->can_retry();

        # If OTP is also enabled, then prompt the user for the desired authentication method.
        return _prompt_for_authn_method(_create_new_state(), msg_enter_authn_method_after_one_touch())
            if cfg_auth_otp_enabled();
    }
}

sub _send_otp_request_and_prompt_for_otp {
    my ($state, $message) = @_;

    # Send an OTP request.
    eval {
        _send_otp_request($state->get_id());
    };
    return _reply(RLM_MODULE_FAIL, $@) if $@;

    # Prompt the user for the OTP.
    radiusd::radlog(L_DBG, msg_asking_for_otp());
    return _challenge($state, REPLY_TYPE_OTP, $message // msg_enter_otp());
}

sub _send_otp_request {
    my ($id) = @_;

    # Create the web user agent.
    my $user_agent = _create_web_user_agent(sandbox => cfg_otp_use_sandbox_api());

    # Send the OTP request.
    my $res = $user_agent->get(cfg_otp_sms_url($id));
    eval {
        _ensure_external_response($res);
    };
    die err_otp_request_failed($@)."\n" if $@;

    # Convert the response content to JSON.
    my $res_content = $res->decoded_content();
    my $res_json = eval { decode_json($res_content) };
    die err_invalid_otp_response($@)."\n" if $@;

    # Extract the response message.
    my $res_code = $res->code();
    if ($res_code == HTTP_OK) {
        # Return whether or not the SMS response was honored.
        return !$res_json->{ignored};
    }

    # Fail with the Authy-specified error message.
    die err_otp_request_failed($res_json->{message} // $res_content)."\n";
}

sub _is_correct_otp {
    my ($id, $otp) = @_;

    # Fail immediately if the OTP cannot be invalid.
    return 0 unless _looks_like_valid_otp($otp);

    # Create the web user agent.
    my $user_agent = _create_web_user_agent(sandbox => cfg_otp_use_sandbox_api());

    # Send the OTP verification request.
    my $res = $user_agent->get(cfg_otp_verification_url($otp, $id));
    eval {
        _ensure_external_response($res);
    };
    die err_otp_verification_request_failed($@)."\n" if $@;

    # Return with "valid" immediately if 200 OK was returned.
    my $res_code = $res->code();
    return 1 if $res_code == HTTP_OK;

    # Convert the response content to JSON.
    my $res_content = $res->decoded_content();
    my $res_json = eval { decode_json($res_content) };
    die err_invalid_otp_response($@)."\n" if $@;

    # Return with "invalid" if 401 Unauthorized was returned with no addition error message.
    my $res_error_code = $res_json->{error_code};
    return 0 if $res_code == HTTP_UNAUTHORIZED && defined $res_error_code && $res_error_code == "60020";

    # Fail with the Authy-specified error message.
    die err_otp_verification_request_failed($res_json->{message} // $res_content)."\n";
}

sub _create_one_touch_approval_request {
    my ($id) = @_;

    # Create the web user agent.
    my $user_agent = _create_web_user_agent(sandbox => cfg_one_touch_use_sandbox_api());

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
        message           => msg_one_touch_prompt(),
        seconds_to_expire => cfg_one_touch_approval_request_timeout(),
        logos             => \@logos,
    };
    my $res = $user_agent->post(cfg_one_touch_approval_request_creation_url($id),
        Content_Type => 'application/json',
        Content => encode_json($data));
    eval {
        _ensure_external_response($res);
    };
    die err_one_touch_approval_request_creation_failed($@)."\n" if $@;

    # Convert the response content to JSON.
    my $res_content = $res->decoded_content();
    my $res_json = eval { decode_json($res_content) };
    die err_invalid_one_touch_approval_request_creation_response($@)."\n" if $@;

    # Extract the response details.
    my $res_code = $res->code();
    if ($res_code == HTTP_OK) {
        # Extract the request UUID.
        return $res_json->{approval_request}->{uuid};
    }

    # Fail with the Authy-specified error message.
    die err_one_touch_approval_request_creation_failed($res_json->{message} // $res_content)."\n";
}

sub _poll_one_touch_endpoint {
    my ($request_uuid) = @_;

    # Create the web user agent.
    my $user_agent = cfg_one_touch_use_custom_polling_endpoint()
        ? _create_web_user_agent(
            sandbox => cfg_one_touch_use_sandbox_api(),
            verify_hostname => cfg_one_touch_verify_custom_polling_endpoint_hostname(),
            ca_file => cfg_one_touch_custom_polling_endpoint_ca_file(),
            ca_path => cfg_one_touch_custom_polling_endpoint_ca_path())
        : _create_web_user_agent(sandbox => cfg_one_touch_use_sandbox_api());

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
        my $error_message = err_one_touch_endpoint_polling_failed($@);
        radiusd::radlog(L_ERR, $error_message);
        die "$error_message\n";
    }

    return cfg_one_touch_use_custom_polling_endpoint()
        ? _parse_custom_one_touch_endpoint_response($res)
        : _parse_authy_one_touch_endpoint_response($res);
}

sub _parse_authy_one_touch_endpoint_response {
    my ($res) = @_;

    # Convert the response content to JSON.
    my $res_content = $res->decoded_content();
    my $res_json = eval { decode_json($res_content) };
    die err_invalid_one_touch_endpoint_response($@)."\n" if $@;

    # Extract the response details.
    my $res_code = $res->code();
    if ($res_code == HTTP_OK) {
        # Extract the status.
        my $status = $res_json->{approval_request}->{status};
        return _ONE_TOUCH_APPROVED if $status eq 'approved';
        return _ONE_TOUCH_DENIED if $status eq 'denied';
        return _ONE_TOUCH_EXPIRED if $status eq 'expired';
        return _ONE_TOUCH_PENDING if $status eq 'pending';
        die err_invalid_one_touch_approval_request_status($status)."\n" if defined $status;
        die err_no_one_touch_approval_request_status()."\n";
    }

    # Fail with the Authy-specified error message.
    die err_one_touch_endpoint_polling_failed($res_json->{message} // $res_content)."\n";
}

sub _parse_custom_one_touch_endpoint_response {
    my ($res) = @_;

    # Convert the response content to JSON.
    my $res_content = $res->decoded_content();
    die err_invalid_one_touch_endpoint_response($@)."\n" if $@;

    # Extract the response details.
    my $res_code = $res->code();
    if ($res_code == HTTP_OK) {
        # Extract the status.
        return _ONE_TOUCH_APPROVED if $res_content eq 'approved';
        return _ONE_TOUCH_DENIED if $res_content eq 'denied';
        die err_invalid_one_touch_approval_request_status($res_content)."\n" if $res_content;
        die err_no_one_touch_approval_request_status()."\n";
    }
    return _ONE_TOUCH_PENDING if $res_code == HTTP_NO_CONTENT;

    # Fail with the endpoint response data.
    die err_one_touch_endpoint_polling_failed(length($res_content) ? $res_content : $res_code)."\n";
}

sub _prompt_for_authn_method {
    my ($state, $message) = @_;
    radiusd::radlog(L_DBG, msg_asking_for_authn_method());
    return _challenge($state, REPLY_TYPE_METHOD_DECISION, $message // msg_enter_authn_method());
}

sub _looks_like_valid_id {
    my ($id) = @_;
    return $id =~ /^\d+$/;
}

sub _looks_like_valid_otp {
    my ($otp) = @_;
    return $otp =~ /^\d{6,8}$/ && length $otp == cfg_otp_length();
}

sub _create_new_state {
    my ($reply_type) = @_;
    return HCM::AuthyState->new(
        id => $RAD_REQUEST{cfg_radius_id_param()},
        tries_remaining => cfg_auth_max_attempts(),
        reply_type => $reply_type
    );
}

sub _decode_state {
    my ($encoded_state) = @_;
    return defined $encoded_state ? HCM::AuthyState->load($encoded_state // $RAD_REQUEST{'State'}) : undef;
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

sub _reply {
    my ($code, $message) = @_;

    if (defined $message) {
        $message =~ s/\s+$//g; # Trim the message.
        $RAD_REPLY{'Reply-Message'} = $message;
    }
    return $code;
}

sub _create_web_user_agent {
    my %options = (
        sandbox         => 0,
        verify_hostname => 1,
        ca_file         => undef,
        ca_path         => undef,
        @_
    );

    my $user_agent = LWP::UserAgent->new(cookie_jar => {},);
    $user_agent->default_header(
        'X-Authy-API-Key' => $options{sandbox} ? cfg_auth_sandbox_api_key() : cfg_auth_production_api_key()
    );
    $user_agent->ssl_opts(verify_hostname => $options{verify_hostname});
    $user_agent->ssl_opts(SSL_ca_file => $options{ca_file});
    $user_agent->ssl_opts(SSL_ca_path => $options{ca_path});
    return $user_agent;
}

sub _ensure_external_response {
    my ($res) = @_;
    my $client_warning = $res->header('Client-Warning');
    if (defined $client_warning && $client_warning eq "Internal response") { # i.e., an internal error
        die $res->decoded_content()."\n";
    }
}

sub detach {
    if (defined $_ID_STORE_MODULE && $_ID_STORE_MODULE->can('destroy')) {
        $_ID_STORE_MODULE->destroy();
    }
}

1;

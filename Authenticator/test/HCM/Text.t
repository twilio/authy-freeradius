#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Test::More;

use_ok('HCM::Text');
use HCM::Text;

isnt(msg_using_default_value('1', '2', '3'), undef, "msg_using_default_value");

isnt(msg_splitting_password(';'), undef, "msg_splitting_password");
isnt(msg_updating_auth_type_to_reply('authy-reply'), undef, "msg_updating_auth_type_to_reply");

isnt(msg_asking_for_authn_method(), undef, "msg_asking_for_authn_method");
isnt(msg_unexpected_authy_response(500, 'Server Error'), undef, "msg_unexpected_authy_response");

isnt(msg_verifying_otp(), undef, "msg_verifying_otp");
isnt(msg_asking_for_otp(), undef, "msg_asking_for_otp");
isnt(msg_otp_accepted(), undef, "msg_otp_accepted");
isnt(msg_otp_rejected(), undef, "msg_otp_rejected");

isnt(msg_one_touch_prompt(), undef, "msg_one_touch_prompt");
isnt(msg_polling_one_touch_endpoint(), undef, "msg_polling_one_touch_endpoint");
isnt(msg_one_touch_approved(), undef, "msg_one_touch_approved");
isnt(msg_one_touch_denied(), undef, "msg_one_touch_denied");
isnt(msg_one_touch_expired(), undef, "msg_one_touch_expired");

isnt(msg_retrieving_id("Username"), undef, "msg_retrieving_id");

isnt(msg_enter_authn_method(), undef, "msg_enter_authn_method");
isnt(msg_reenter_authn_method(), undef, "msg_reenter_authn_method");
isnt(msg_enter_authn_method_after_otp(), undef, "msg_enter_authn_method_after_otp");
isnt(msg_enter_authn_method_after_one_touch(), undef, "msg_enter_authn_method_after_one_touch");
isnt(msg_enter_otp(), undef, "msg_enter_otp");
isnt(msg_reenter_otp(), undef, "msg_reenter_otp");
isnt(msg_authn_succeeded(), undef, "msg_authn_succeeded");
isnt(msg_authn_failed(), undef, "msg_authn_failed");

isnt(err_invalid_config_int('Integers', 'IntOpt', 'int_int'), undef, "err_invalid_config_int");
isnt(err_invalid_config_bool('Bools', 'BoolOpt', 'inv_bool'), undef, "err_invalid_config_bool");
isnt(err_id_and_otp_params_conflict(), undef, "err_id_and_otp_params_conflict");
isnt(err_no_production_api_key(), undef, "err_no_production_api_key");
isnt(err_no_sandbox_api_key(), undef, "err_no_sandbox_api_key");
isnt(err_invalid_production_api_key_verification_response("R"), undef, "err_invalid_production_api_key_verification_response");
isnt(err_invalid_sandbox_api_key_verification_response("V"), undef, "err_invalid_sandbox_api_key_verification_response");
isnt(err_production_api_key_verification_failed("Why"), undef, "err_production_api_key_verification_failed");
isnt(err_sandbox_api_key_verification_failed("Why not"), undef, "err_sandbox_api_key_verification_failed");
isnt(err_invalid_production_api_key(), undef, "err_invalid_production_api_key");
isnt(err_invalid_sandbox_api_key(), undef, "err_invalid_sandbox_api_key");
isnt(err_invalid_max_attempt_count(), undef, "err_invalid_max_attempt_count");
isnt(err_no_authn_methods(), undef, "err_no_authn_methods");
isnt(err_no_otp_option(), undef, "err_no_otp_option");
isnt(err_no_one_touch_option(), undef, "err_no_one_touch_option");
isnt(err_otp_and_one_touch_options_conflict(), undef, "err_otp_and_one_touch_options_conflict");
isnt(err_no_otp_delimiter(), undef, "err_no_otp_delimiter");
isnt(err_invalid_otp_length(1, 2), undef, "err_invalid_otp_length");
isnt(err_invalid_one_touch_polling_interval(), undef, "err_invalid_one_touch_polling_interval");
isnt(err_invalid_one_touch_approval_request_timeout(), undef, "err_invalid_one_touch_approval_request_timeout");
isnt(err_no_one_touch_default_logo_url(), undef, "err_no_one_touch_default_logo_url");

isnt(err_invalid_state('BAD_STATE_DATA'), undef, "err_invalid_state");

isnt(err_unexpected_otp_param(), undef, "err_unexpected_otp_param");
isnt(err_no_user_name_in_request(), undef, "err_no_user_name_in_request");
isnt(err_no_password_in_request(), undef, "err_no_password_in_request");
isnt(err_no_id_in_request(), undef, "err_no_id_in_request");
isnt(err_no_otp_in_request(), undef, "err_no_otp_in_request");
isnt(err_no_challenge_response_in_request(), undef, "err_no_challenge_response_in_request");
isnt(err_id_retrieval_failed("Oops"), undef, "err_id_retrieval_failed");
isnt(err_invalid_id("1a2b3c4d"), undef, "err_invalid_id");
isnt(err_no_id_found_for_user(), undef, "err_no_id_found_for_user");

isnt(err_invalid_otp(), undef, "err_invalid_otp");
isnt(err_otp_request_failed("Something's wrong"), undef, "err_otp_request_failed");
isnt(err_invalid_otp_response("This is why"), undef, "err_invalid_otp_response");
isnt(err_otp_verification_request_failed("Things aren't working"), undef, "err_otp_verification_request_failed");
isnt(err_invalid_otp_verification_response("No idea"), undef, "err_invalid_otp_verification_response");

isnt(err_one_touch_approval_request_creation_failed("Beats me"), undef, "err_one_touch_approval_request_creation_failed");
isnt(err_invalid_one_touch_approval_request_creation_response("Let me get back to you"), undef, "err_invalid_one_touch_approval_request_creation_response");
isnt(err_one_touch_endpoint_polling_failed("Endpoint is broken"), undef, "err_one_touch_endpoint_polling_failed");
isnt(err_invalid_one_touch_endpoint_response("TerribleResponse"), undef, "err_invalid_one_touch_endpoint_response");
isnt(err_invalid_one_touch_approval_request_status("InvalidStatus"), undef, "err_invalid_one_touch_approval_request_status");
isnt(err_no_one_touch_approval_request_status(), undef, "err_no_one_touch_approval_request_status");

isnt(err_id_store_script_load_failed("Reason"), undef, "err_id_store_script_load_failed");
isnt(err_invalid_id_store_script(), undef, "err_invalid_id_store_script");

done_testing();

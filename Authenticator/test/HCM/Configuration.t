#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Test::More;

use_ok('HCM::Configuration');
use HCM::Configuration;

isnt(cfg_radius_id_param(), undef, "cfg_radius_id_param");
isnt(cfg_radius_otp_param(), undef, "cfg_radius_otp_param");
isnt(cfg_radius_reply_auth_type(), undef, "cfg_radius_reply_auth_type");
isnt(cfg_radius_state_marker(), undef, "cfg_radius_state_marker");

if ((cfg_auth_otp_enabled() && !cfg_otp_use_sandbox_api())
    || (cfg_auth_one_touch_enabled() && !cfg_one_touch_use_sandbox_api())) {
    isnt(cfg_auth_production_api_key(), undef, "cfg_auth_production_api_key");
}
if ((cfg_auth_otp_enabled() && cfg_otp_use_sandbox_api())
    || (cfg_auth_one_touch_enabled() && cfg_one_touch_use_sandbox_api())) {
    isnt(cfg_auth_sandbox_api_key(), undef, "cfg_auth_sandbox_api_key");
}
isnt(cfg_auth_interactive(), undef, "cfg_auth_interactive");
ok(cfg_auth_max_attempts() > 0, "cfg_auth_max_attempts");
if (cfg_auth_interactive() && cfg_auth_otp_and_one_touch_enabled()) {
    isnt(cfg_auth_otp_option(), undef, "cfg_auth_otp_option");
    isnt(cfg_auth_one_touch_option(), undef, "cfg_auth_one_touch_option");
}

isnt(cfg_auth_otp_enabled(), undef, "cfg_auth_otp_enabled");
if (cfg_auth_otp_enabled()) {
    isnt(cfg_otp_delimiter(), undef, "cfg_otp_delimiter");
    isnt(cfg_otp_length(), undef, "cfg_otp_length");
    isnt(cfg_otp_use_sandbox_api(), undef, "cfg_otp_use_sandbox_api");
    isnt(cfg_otp_always_send_sms(), undef, "cfg_otp_always_send_sms");
    isnt(cfg_otp_allow_unregistered_users(), undef, "cfg_otp_allow_unregistered_users");
}

isnt(cfg_auth_one_touch_enabled(), undef, "cfg_auth_one_touch_enabled");
if (cfg_auth_one_touch_enabled()) {
    isnt(cfg_one_touch_use_sandbox_api(), undef, "cfg_one_touch_use_sandbox_api");
    if (cfg_one_touch_use_custom_polling_endpoint()) {
        isnt(cfg_one_touch_custom_polling_endpoint_url(), undef, "cfg_one_touch_custom_polling_endpoint_url");
        isnt(
            cfg_one_touch_verify_custom_polling_endpoint_hostname(),
            undef,
            "cfg_one_touch_verify_custom_polling_endpoint_hostname");
    }
    ok(cfg_one_touch_polling_interval() > 0, "cfg_one_touch_polling_interval");
    ok(cfg_one_touch_approval_request_timeout() > 0, "cfg_one_touch_approval_request_timeout");
    if (defined(cfg_one_touch_low_res_logo_url() // cfg_one_touch_med_res_logo_url() // cfg_one_touch_high_res_logo_url())) {
        isnt(cfg_one_touch_default_logo_url(), undef, "cfg_one_touch_default_logo_url");
    }
}

isnt(cfg_id_store(), undef, "cfg_id_store");

is(cfg_auth_silent(), !cfg_auth_interactive(), "cfg_auth_silent");
is(cfg_auth_only_otp_enabled(), cfg_auth_otp_enabled() && !cfg_auth_one_touch_enabled(), "cfg_auth_only_otp_enabled");
is(cfg_auth_only_one_touch_enabled(), cfg_auth_one_touch_enabled() && !cfg_auth_otp_enabled(), "cfg_auth_only_one_touch_enabled");
is(cfg_auth_otp_and_one_touch_enabled(), cfg_auth_otp_enabled() && cfg_auth_one_touch_enabled(), "cfg_auth_otp_and_one_touch_enabled");
if (cfg_auth_otp_enabled()) {
    isnt(cfg_otp_sms_url('1234'), undef, "cfg_otp_sms_url");
    isnt(cfg_otp_verification_url('1234567', '1234'), undef, "cfg_otp_verification_url");
}
if (cfg_auth_one_touch_enabled()) {
    isnt(cfg_one_touch_approval_request_creation_url('1234'), undef, "cfg_one_touch_approval_request_creation_url");
    is(cfg_one_touch_use_custom_polling_endpoint(), defined cfg_one_touch_custom_polling_endpoint_url(), "cfg_one_touch_use_custom_polling_endpoint");
    isnt(cfg_one_touch_polling_endpoint_url('a-b-c-d'), undef, "cfg_one_touch_polling_endpoint_url");
}

done_testing();


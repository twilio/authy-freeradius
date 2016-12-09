#!/usr/local/bin/perl

use 5.010;
use strict;
use warnings FATAL => 'all';

use Data::Dumper;
use Test::More;

use HCM::ModuleUtil;
use HCM::Configuration;

BEGIN {
    require 'HCM/AuthyAuthenticator.pl';
}

our $request = \%main::RAD_REQUEST;
our $check = \%main::RAD_CHECK;
our $reply = \%main::RAD_REPLY;

our %RESPONSE_CODE_NAMES = (
    RLM_MODULE_REJECT()   => "Reject",
    RLM_MODULE_FAIL()     => "Fail",
    RLM_MODULE_OK()       => "OK",
    RLM_MODULE_HANDLED()  => "Handled",
    RLM_MODULE_INVALID()  => "Invalid",
    RLM_MODULE_USERLOCK() => "User Locked",
    RLM_MODULE_NOTFOUND() => "User Not Found",
    RLM_MODULE_NOOP()     => "No-Op",
    RLM_MODULE_UPDATED()  => "Updated",
);
our @GOOD_AUTHZ_RESPONSES = (RLM_MODULE_HANDLED, RLM_MODULE_NOOP, RLM_MODULE_OK, RLM_MODULE_UPDATED);

use constant AUTHY_ID => $ENV{'AUTHY_ID'} // prompt("Authy ID:");
use constant INVALID_AUTHY_ID => '999999999999';
use constant INVALID_OTP => '0000000';

subtest "Sending OTP requests" => sub {
    plan skip_all => "OTP authentication is disabled" unless cfg_auth_otp_enabled();
    plan skip_all => "OTP requests are working.";

    my $req1_honored = eval { _send_otp_request(AUTHY_ID) };
    say $@ if $@;
    ok(!$@, "No OTP request #1 errors");
    ok(!cfg_otp_always_send_sms() || $req1_honored, "OTP request sent successfully");

    eval { _send_otp_request(INVALID_AUTHY_ID); };
    say $@ if $@;
    ok($@, "OTP request #1 errors");
};

subtest "Creating OneTouch approval requests" => sub {
    plan skip_all => "OneTouch authentication is disabled" unless cfg_auth_one_touch_enabled();
    plan skip_all => "OneTouch approval requests are working.";

    my $req1_uuid = eval { _create_one_touch_approval_request(AUTHY_ID); };
    say $@ if $@;
    ok(!$@, "No OneTouch approval request creation #1 errors");
    ok($req1_uuid, "Request UUID returned");
    if ($req1_uuid) {
        say "Request UUID: $req1_uuid";
    }

    eval { _create_one_touch_approval_request(INVALID_AUTHY_ID); };
    say $@ if $@;
    ok($@, "OneTouch approval request creation #2 errors");
};

subtest "Verifying OTPs" => sub {
    plan skip_all => "OTP verification is working.";

    my $token1_valid = eval { _is_correct_otp(AUTHY_ID, prompt("OTP: ")); };
    say $@ if $@;
    ok(!$@, "No OTP verification request #1 errors");
    ok($token1_valid, "Valid OTP detected");

    my $token2_valid = eval { _is_correct_otp(AUTHY_ID, INVALID_OTP); };
    say $@ if $@;
    ok(!$@, "No OTP verification request #2 errors");
    ok(!$token2_valid, "Invalid OTP detected");

    my $token3_valid = eval { _is_correct_otp(INVALID_AUTHY_ID, prompt("OTP: ")); };
    say $@ if $@;
    ok($@, "OTP verification request #3 errors");
    ok(!$token3_valid, "Invalid Authy ID detected");
};

subtest "Verifying OneTouch against Authy OneTouch endpoint" => sub {
    plan skip_all => "Using custom OneTouch endpoint instead" if cfg_one_touch_use_custom_polling_endpoint();
    plan skip_all => "OneTouch verification against Authy is working.";

    test_one_touch_directly();
};

subtest "Verifying OneTouch against a custom endpoint" => sub {
    plan skip_all => "Using Authy OneTouch endpoint instead" unless cfg_one_touch_use_custom_polling_endpoint();
    # plan skip_all => "OneTouch verification against a custom endpoint is working.";

    test_one_touch_directly();
};

subtest "Silent OTP RADIUS authentication" => sub {
    plan skip_all => "Silent OTP not enabled" unless cfg_auth_silent() && cfg_auth_otp_enabled();
    plan skip_all => "Silent OTP is working";

    say "Please enter the correct OTP";
    is(simulate_radius(password => "Password1;".prompt("OTP: ")), RLM_MODULE_OK, "Valid OTP detected");

    is(simulate_radius(assword => "Password1;abc"), RLM_MODULE_REJECT, "Invalid OTP detected");
    is(simulate_radius(password => "Password1;0000000"), RLM_MODULE_REJECT, "Incorrect OTP detected");
};

subtest "Interactive OTP RADIUS authentication" => sub {
    plan skip_all => "Interactive OTP not enabled" unless cfg_auth_interactive() && cfg_auth_otp_enabled();
    plan skip_all => "Interactive OTP is working";

    say "Please enter the correct OTP";
    is(simulate_radius(), RLM_MODULE_OK, "Valid OTP detected");

    say "Please enter an invalid OTP";
    is(simulate_radius(), RLM_MODULE_REJECT, "Invalid OTP detected");

    say "Please enter a valid but incorrect OTP";
    is(simulate_radius(), RLM_MODULE_REJECT, "Incorrect OTP detected");
};

subtest "Silent OneTouch RADIUS authentication" => sub {
    plan skip_all => "Silent OneTouch not enabled" unless cfg_auth_silent() && cfg_auth_one_touch_enabled();
    plan skip_all => "Silent OneTouch is working";

    say "Please approve the OneTouch request";
    is(simulate_radius(), RLM_MODULE_OK, "Valid OTP detected");

    say "Please deny the OneTouch request";
    is(simulate_radius(), RLM_MODULE_REJECT, "Invalid OTP detected");

    say "Please allow the OneTouch request to expire";
    is(simulate_radius(), RLM_MODULE_REJECT, "Incorrect OTP detected");
};

subtest "General RADIUS authentication" => sub {
    # plan skip_all => "Silent OneTouch not enabled" unless cfg_auth_silent() && cfg_one_touch_enabled();
    # plan skip_all => "Silent OneTouch is working";

    say "Please authenticate successfully";
    is(simulate_radius(password => prompt("Password: ")), RLM_MODULE_OK, "Authentication succeeded");

    say "Please fail to authenticate";
    is(simulate_radius(password => prompt("Password: ")), RLM_MODULE_REJECT, "Authentication failed");
};

sub test_one_touch_directly () {
    say "Please approve your OneTouch approval request.";
    my $ot_status1 = eval {
        _poll_one_touch_endpoint(_create_one_touch_approval_request(AUTHY_ID));
    };
    say $@ if $@;
    ok(!$@, "No OneTouch endpoint poll #1 errors");
    is($ot_status1, &_ONE_TOUCH_APPROVED, "OneTouch approval request approved");

    say "Please deny your OneTouch approval request.";
    my $ot_status2 = eval {
        _poll_one_touch_endpoint(_create_one_touch_approval_request(AUTHY_ID));
    };
    say $@ if $@;
    ok(!$@, "No OneTouch endpoint poll #2 errors");
    is($ot_status2, &_ONE_TOUCH_DENIED, "OneTouch approval request denied");

    say "Please allow your OneTouch approval request to expire.";
    my $ot_status3 = eval {
        _poll_one_touch_endpoint(_create_one_touch_approval_request(AUTHY_ID));
    };
    say $@ if $@;
    ok(!$@, "No OneTouch endpoint poll #3 errors");
    is($ot_status3, &_ONE_TOUCH_EXPIRED, "OneTouch approval request expired");
}

sub simulate_radius (%) {
    my (%options) = @_;
    %$request = (
        'User-Name'           => $options{username} // 'gmoore',
        'User-Password'       => $options{password} // 'Password1',
        cfg_radius_id_param() => $options{id} // AUTHY_ID,
    );

    my $pass = 1;
    my $debug = 0;
    while (1) {
        say "";
        say "--- Pass $pass ---";
        say "";

        my $authorize_response = authorize();
        if ($debug) {
            say "Authorize Results:";
            say "Return code = ".$RESPONSE_CODE_NAMES{$authorize_response};
            print "RAD_REQUEST = ".Dumper($request);
            print "RAD_CHECK = ".Dumper($check);
            print "RAD_REPLY = ".Dumper($reply);
        }
        if (!($authorize_response ~~ @GOOD_AUTHZ_RESPONSES)) {
            if (defined $reply->{'Reply-Message'}) {
                say $reply->{'Reply-Message'};
            }
            say "Stopping." if $debug;
            return $authorize_response;
        }
        say "";

        my $authenticate_response = authenticate();
        if ($debug) {
            say "Authenticate Results:";
            say "Return code = ".$RESPONSE_CODE_NAMES{$authenticate_response};
            print "RAD_REQUEST = ".Dumper($request);
            print "RAD_CHECK = ".Dumper($check);
            print "RAD_REPLY = ".Dumper($reply);
        }
        if ($authenticate_response != RLM_MODULE_HANDLED || $check->{'Response-Packet-Type'} ne 'Access-Challenge') {
            if (defined $reply->{'Reply-Message'}) {
                say $reply->{'Reply-Message'};
            }
            say "Stopping." if $debug;
            return $authenticate_response;
        }
        say "";

        %$request = ();
        $request->{'User-Name'} = 'testuser';
        $request->{'User-Password'} = prompt($reply->{'Reply-Message'}."\nResponse: ");
        $request->{'State'} = '0x'.unpack('H*', $reply->{'State'});
        %$check = ();
        %$reply = ();

        ++$pass;
    }
}

sub prompt {
    my ($text) = @_;
    print $text;
    my $input = <STDIN>;
    chomp($input);
    return $input;
}

done_testing();

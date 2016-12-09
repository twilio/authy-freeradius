package HCM::IDStores::CSV;

use 5.010;
use strict;
use warnings FATAL => 'all';

use Carp qw(croak);
use Encode qw(encode);
use HCM::ModuleUtil;
use HCM::Text;
use Parse::CSV;

eval "use radiusd"; # For local testing.

our ($_FILE, $_SEPARATOR, $_QUOTE, $_ESCAPE_CHAR, $_USER_NAME_INDEX, $_ID_INDEX);
our ($_MSG, $_ERR);

# Configuration option names:
use constant {
    _OPT_FILE                    => 'File',
    _OPT_SEPARATOR               => 'Separator',
    _OPT_QUOTE                   => 'Quote',
    _OPT_ESCAPE_CHARACTER        => 'EscapeCharacter',
    _OPT_USER_NAME_COLUMN_NUMBER => 'UserNameColumnNumber',
    _OPT_ID_COLUMN_NUMBER        => 'IDColumnNumber',
};

# Default configuration values:
use constant {
    _DEF_FILE                    => undef,
    _DEF_SEPARATOR               => ',',
    _DEF_QUOTE                   => '"',
    _DEF_ESCAPE_CHARACTER        => '"',
    _DEF_USER_NAME_COLUMN_NUMBER => undef,
    _DEF_ID_COLUMN_NUMBER        => undef,
};

# Errors:
use constant {
    _ERR_ID_CANNOT_OPEN_FILE => 'CannotOpenFile',
    _ERR_ID_PARSING_FAILED   => 'ParsingFailed',
};

sub initialize {
    shift; # Skip the class name
    my (%params) = (
        config   => {},
        messages => {},
        errors   => {},
        @_
    );

    my $config = $params{config};
    $_MSG = $params{messages};
    $_ERR = $params{errors};

    # Load the configuration options.
    $_FILE = _get_value($config, _OPT_FILE, _DEF_FILE);
    $_SEPARATOR = _get_value($config, _OPT_SEPARATOR, _DEF_SEPARATOR);
    $_QUOTE = _get_value($config, _OPT_QUOTE, _DEF_QUOTE);
    $_ESCAPE_CHAR = _get_value($config, _OPT_ESCAPE_CHARACTER, _DEF_ESCAPE_CHARACTER);
    my $user_name_column_number = _get_value($config, _OPT_USER_NAME_COLUMN_NUMBER, _DEF_USER_NAME_COLUMN_NUMBER);
    my $id_column_number = _get_value($config, _OPT_ID_COLUMN_NUMBER, _DEF_ID_COLUMN_NUMBER);

    # Validate the configuration options.
    die "Flat file field separator must be eight bytes or less in length\n" if length(encode('UTF-8', $_SEPARATOR)) > 8;
    die "Flat file quote string must be eight bytes or less in length\n" if length(encode('UTF-8', $_QUOTE)) > 8;
    die "Flat file field separator and quote string must differ\n" if $_SEPARATOR eq $_QUOTE;
    die "Flat file escape char must be a single character\n" if length(encode('UTF-8', $_ESCAPE_CHAR)) > 1;
    die "Invalid flat file user name column number '$user_name_column_number'"
        unless $user_name_column_number =~ /^\d*$/;
    die "Flat file user name column number must be at least 1" unless $user_name_column_number >= 1;
    die "Invalid flat file user name column number '$id_column_number'" unless $id_column_number =~ /^\d*$/;
    die "Flat file user name column number must be at least 1" unless $id_column_number >= 1;

    $_USER_NAME_INDEX = $user_name_column_number - 1;
    $_ID_INDEX = $id_column_number - 1;

    # Ensure that the messages were loaded.
    _ensure_err($_ERR, _ERR_ID_CANNOT_OPEN_FILE);
    _ensure_err($_ERR, _ERR_ID_PARSING_FAILED);
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

    open my $csv_fh, '<:encoding(UTF-8)', $_FILE
        or die "Unable to open flatfile at $_FILE: $!";
    my $parser = Parse::CSV->new(
        handle => $csv_fh,
        csv_attr => {
            binary      => 1,
            sep         => $_SEPARATOR,
            quote       => $_QUOTE,
            escape_char => $_ESCAPE_CHAR,
        },
    );

    # Search each entry for a matching user.
    my $lc_user_name = lc $user_name;
    while (my $entry = $parser->fetch()) {
        if ($lc_user_name eq lc $entry->[$_USER_NAME_INDEX]) {
            return $entry->[$_ID_INDEX];
        }
    }
    if ($parser->errstr) {
        die sprintf($_ERR->{_ERR_ID_PARSING_FAILED()}, $parser->errstr);
    }
}

1;

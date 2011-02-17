#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'LWP::Protocol::ldap' ) || print "Bail out!
";
}

diag( "Testing LWP::Protocol::ldap $LWP::Protocol::ldap::VERSION, Perl $], $^X" );

use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'LWP::Protocol::ldap',
    license             => 'perl',
    dist_author         => q{Jef Le_Ponot <jef_le_ponot@voila.fr>},
    dist_version_from   => 'lib/LWP/Protocol/ldap.pm',
    build_requires => {
        'Test::More' => 0,
    },
    add_to_cleanup      => [ 'LWP-Protocol-ldap-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();

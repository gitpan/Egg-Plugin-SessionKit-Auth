use inc::Module::Install;

name         'Egg-Plugin-SessionKit-Auth';
all_from     'lib/Egg/Plugin/SessionKit/Auth.pm';
version_from 'lib/Egg/Plugin/SessionKit/Auth.pm';
author       'Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>';
license      'perl';

requires 'Egg::Release'            => 2.00;
requires 'Egg::Plugin::SessionKit' => 2.00;
requires 'Egg::Plugin::Crypt::CBC' => 2.00;
requires 'Egg::Model::DBIC'        => 2.00;

build_requires 'Test::Simple';
build_requires 'Test::Pod';
build_requires 'Test::Perl::Critic';
build_requires 'Test::Pod::Coverage';

use_test_base;
auto_include;
WriteAll;

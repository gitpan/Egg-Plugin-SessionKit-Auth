use inc::Module::Install;
name 'Egg-Plugin-SessionKit-Auth';
all_from 'lib/Egg/Plugin/SessionKit/Auth.pm';
version_from 'lib/Egg/Plugin/SessionKit/Auth.pm';

requires 'DBIx::Class'             => 0.07999;
requires 'Egg::Release'            => 1.13;
requires 'Egg::Model::DBIC'        => 0.03;
requires 'Egg::Plugin::Crypt::CBC' => 0.01;
requires 'Egg::Plugin::SessionKit' => 0.07;

build_requires 'Test::More';
build_requires 'Test::Pod';

use_test_base;
auto_include;
WriteAll;

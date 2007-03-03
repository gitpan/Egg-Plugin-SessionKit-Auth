use Module::Build;

my $builder = Module::Build->new(
  module_name => 'Egg::Plugin::SessionKit::Auth',
  license => 'perl',
  dist_author => 'Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>',
  dist_version_from=> 'lib/Egg/Plugin/SessionKit/Auth.pm',
  requires => {
    'DBIx::Class'             => 0.07999,
    'Egg::Release'            => 1.13,
    'Egg::Model::DBIC'        => 0.03,
    'Egg::Plugin::Crypt::CBC' => 0.01,
    'Egg::Plugin::SessionKit' => 0.07,
    'Test::More' => 0,
    'Test::Pod'  => 0,
    },
  );

$builder->create_build_script();

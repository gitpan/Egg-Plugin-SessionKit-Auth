use Module::Build;

my $builder = Module::Build->new(

  module_name => 'Egg::Plugin::SessionKit::Auth',
  dist_version_from=> 'lib/Egg/Plugin/SessionKit/Auth.pm',
  dist_author => 'Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>',
  license => 'perl',

  requires => {

    'Egg::Release'            => 2.00,
    'Egg::Plugin::SessionKit' => 2.00,
    'Egg::Plugin::Crypt::CBC' => 2.00,
    'Egg::Model::DBIC'        => 2.00,

    'Test::Simple'          => 0,
    'Test::Pod'             => 0,
    'Test::Perl::Critic'    => 0,
    'Test::Pod::Coverage'   => 0,
    },
  );

$builder->create_build_script();

use Module::Build;

my $builder = Module::Build->new(

  module_name       => 'Egg::Plugin::SessionKit::Auth',
  dist_version_from => 'lib/Egg/Plugin/SessionKit/Auth.pm',
  dist_abstract     => 'lib/Egg/Plugin/SessionKit/Auth.pm',
  dist_author       => 'Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>',
  license           => 'perl',

  requires => {

    'Egg::Release'            => 2.25,
    'Egg::Plugin::SessionKit' => 2.10,
    'Egg::Plugin::Crypt::CBC' => 2.02,
#    'Egg::Model::DBIC'        => 2.00,

    'Test::More'           => 0,
    'Test::Pod'            => 0,
    'Test::Perl::Critic'   => 0,
    'Test::Pod::Coverage'  => 0,
    },
  );

$builder->create_build_script();

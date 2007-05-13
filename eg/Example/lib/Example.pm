package Example;
use strict;
use warnings;
use Egg qw/ -Debug
  SessionKit::Auth::DBIC
  Dispatch::Fast
  Debugging
  Log
  DBIC::Transaction
  /;

our $VERSION= '0.01';

__PACKAGE__->egg_startup(

  title      => 'Example',
  root       => '/path/to/Example',
  static_uri => '/',
  dir => {
    lib      => '< $e.root >/lib',
    static   => '< $e.root >/htdocs',
    etc      => '< $e.root >/etc',
    cache    => '< $e.root >/cache',
    tmp      => '< $e.root >/tmp',
    template => '< $e.root >/root',
    comp     => '< $e.root >/comp',
    },
  template_path=> ['< $e.dir.template >', '< $e.dir.comp >'],

  MODEL => [ [ DBIC => {} ] ],

  plugin_session => {
    base  => [ DBIC => {
      schema_name=> 'MySchema',
      source_name=> 'Sessions',
      } ],
    store => 'Base64',
    auth  => {
      model_name      => 'myschema:members',
      uid_db_field    => 'uid',
      psw_db_field    => 'psw',
      active_db_field => 'active',
      },
    },

  );

# Dispatch. ------------------------------------------------
__PACKAGE__->run_modes(
  _default => sub {
    my($dispatch, $e)= @_;
    require Egg::Helper::BlankPage;
    $e->response->body( Egg::Helper::BlankPage->out($e) );
    },
  );
# ----------------------------------------------------------

1;

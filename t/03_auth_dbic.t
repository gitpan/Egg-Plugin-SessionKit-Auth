
use Test::More qw/no_plan/;
use Egg::Helper::VirtualTest;

my $dsn   = $ENV{EGG_RDBMS_DSN}        || "";
my $uid   = $ENV{EGG_RDBMS_USER}       || "";
my $psw   = $ENV{EGG_RDBMS_PASSWORD}   || "";
my $table = $ENV{EGG_RDBMS_TEST_TABLE} || 'egg_plugin_auth_table';

SKIP: {
skip q{ Data base is not setup. } unless ($dsn and $uid);

eval{ require Egg::Model::DBIC };
skip q{ 'Egg::Model::DBIC' module is not installed. } if $@;

eval{ require DBIx::Class::ResultClass::HashRefInflator };
skip q{ 'DBIx::Class::ResultClass::HashRefInflator' is not installed. } if $@;

my $v= Egg::Helper::VirtualTest->new;

@{$v->global}
 {qw/dbic_dsn dbic_uid dbic_psw dbic_table/}= ($dsn, $uid, $psw, $table);

$v->prepare(
  controller => { egg_includes => [qw/ SessionKit::Auth::DBIC /] },
  config => {
    MODEL=> [ [ DBIC=> {} ] ],
    plugin_session => { auth=> {
      model_name      => 'schema:session',
      uid_db_field    => 'uid',
      psw_db_field    => 'psw',
      active_db_field => 'active',
      } },
    },
  create_files => [$v->yaml_load( join '', <DATA> )],
  );

ok my $e= $v->egg_pcomp_context;
my $dbh= $e->model('schema')->storage->dbh;
eval{
$dbh->do(<<END_CREATE);
CREATE TABLE $table (
  id       int2      primary key,
  uid      varchar,
  psw      varchar,
  active   int2,
  email    varchar,
  nickname varchar
  );
END_CREATE

my $sth= $dbh->prepare(
    qq{ INSERT INTO $table (id, uid, psw, active, email, nickname)}
  . qq{ VALUES (?, ?, ?, ?, ?, ?) }
  );
for my $in (
  [qw/ 1 foo 12345 1 foo@email.domain binbin /],
  [qw/ 2 boo 23456 1 boo@email.domain bonbon /],
  [qw/ 3 zuu 34567 0 boo@email.domain zuuzuu /],
  [qw/ 4 hoo     0 1 hoo@email.domain hoohoo /],
  ) { $sth->execute(@$in) }

ok my $auth= $e->auth;
isa_ok $auth, 'Egg::Plugin::SessionKit::Auth::DBIC::handler';
isa_ok $auth, 'Egg::Plugin::SessionKit::Auth::handler';
isa_ok $auth, 'Egg::Plugin::SessionKit::Auth::Crypt::Plain';
can_ok $auth, qw/
  e config user user_name get_uid_param get_psw_param messages session errstr
  error_uid_undefined error_psw_undefined error_no_regist error_unactive
  error_discord_psw error_unset_psw error_secure_onry
  logout error errstr _get_login_argument psw_check restore _search
  /;

my $request= $e->request;
ok ! $auth->login;
ok $auth->errstr eq 'uid_undefined';

$request->params->{__uid}= 'zuu';

ok ! $auth->login;
ok $auth->errstr eq 'psw_undefined';

$request->params->{__psw}= '34567';

ok ! $auth->login;
ok $auth->errstr eq 'unactive';

$request->params->{__uid}= 'hoge';
$request->params->{__psw}= 'bad password';

ok ! $auth->login;
ok $auth->errstr eq 'no_regist';

$request->params->{__uid}= 'boo';

ok ! $e->auth->login;
ok $auth->errstr eq 'discord_psw';

$request->params->{__uid}= 'hoo';

ok ! $e->auth->login;
ok $auth->errstr eq 'unset_psw';

$request->params->{__uid}= 'foo';
$request->params->{__psw}= '12345';

ok my $user= $auth->login;
ok $user eq $e->session->{auth_data};
ok $auth->user;
ok $auth->user eq $e->session->{auth_data};
ok $auth->user_name;
ok $e->user_name;
ok $e->user_name eq 'foo';
ok $e->user_name eq $auth->user_name;
ok $user->{email};
ok $user->{email} eq 'foo@email.domain';
ok $user->{nickname};
ok $user->{nickname} eq 'binbin';
ok $auth->user->{email};
ok $auth->user->{email} eq $user->{email};
ok $auth->user->{nickname};
ok $auth->user->{nickname} eq $user->{nickname};
ok $auth->logout;
ok ! $e->session->{auth_data};
ok $auth->user;
ok ! $auth->user->{email};
ok ! $e->user_name;
ok ! $auth->user_name;

};
$dbh->do(qq{ DROP TABLE $table });
  };


__DATA__
---
filename: lib/<$e.project_name>/DBIC/Schema.pm
value: |
  package <$e.project_name>::DBIC::Schema;
  use strict;
  use warnings;
  use base qw/Egg::Model::DBIC::Schema/;
  our $VERSION = '0.01';
  
  __PACKAGE__->config(
    dsn      => '<$e.dbic_dsn>',
    user     => '<$e.dbic_uid>',
    password => '<$e.dbic_psw>',
    options  => { AutoCommit => 1, RaiseError=> 1 },
    );
  
  __PACKAGE__->load_classes;
  
  1;
---
filename: lib/<$e.project_name>/DBIC/Schema/Session.pm
value: |
  package <$e.project_name>::DBIC::Schema::Session;
  use strict;
  use warnings;
  use base 'DBIx::Class';
  
  __PACKAGE__->load_components("PK::Auto", "Core");
  __PACKAGE__->table("<$e.dbic_table>");
  __PACKAGE__->add_columns(
    "id",
    {
      data_type => "smallint",
      default_value => undef,
      is_nullable => 0,
      size => 2,
    },
    "uid",
    {
      data_type => "character varying",
      default_value => undef,
      is_nullable => 1,
      size => undef,
    },
    "psw",
    {
      data_type => "character varying",
      default_value => undef,
      is_nullable => 1,
      size => undef,
    },
    "active",
    {
      data_type => "smallint",
      default_value => undef,
      is_nullable => 1,
      size => 2,
    },
    "email",
    {
      data_type => "character varying",
      default_value => undef,
      is_nullable => 1,
      size => undef,
    },
    "nickname",
    {
      data_type => "character varying",
      default_value => undef,
      is_nullable => 1,
      size => undef,
    },
  );
  __PACKAGE__->set_primary_key("id");
  
  1;

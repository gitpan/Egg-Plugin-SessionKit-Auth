
use lib qw{ /home/perl-lib ./lib ../lib };
use Test::More qw/no_plan/;
use Egg::Helper;
my $t= Egg::Helper->run('O:Test');

my @creates= $t->yaml_load( join '', <DATA> );

my $proot= $t->create_project_root;

$t->prepare(
  controller=> { egg=> [qw/ SessionKit::Auth::File /] },
  create_files=> \@creates,
  config=> {
    plugin_session=> {
      auth=> {
        data_path=> "$proot/etc/members.tsv",
        constant => [qw/uid psw active email nickname/],
        uid_db_field=> 'uid',
        psw_db_field=> 'psw',
        active_db_field=> 'active',
        },
      },
    },
  );

print $t->file_view("lib/EggVirtual.pm");

ok( my $e= $t->egg_virtual );
ok( $e->prepare_component );
ok( ! $e->auth->login );
ok( $e->auth->errstr eq 'uid_undefined' );

$e->request->params->{__uid}= 'zuu';

ok( ! $e->auth->login );
ok( $e->auth->errstr eq 'psw_undefined' );

$e->request->params->{__psw}= '34567';

ok( ! $e->auth->login );
ok( $e->auth->errstr eq 'unactive' );

$e->request->params->{__uid}= 'hoge';
$e->request->params->{__psw}= 'bad password';

ok( ! $e->auth->login );
ok( $e->auth->errstr eq 'no_regist' );

$e->request->params->{__uid}= 'boo';

ok( ! $e->auth->login );
ok( $e->auth->errstr eq 'discord_psw' );

$e->request->params->{__uid}= 'hoo';

ok( ! $e->auth->login );
ok( $e->auth->errstr eq 'unset_psw' );

$e->request->params->{__uid}= 'foo';
$e->request->params->{__psw}= '12345';

ok( my $user= $e->auth->login );
ok( $user eq $e->session->{auth_data} );
ok( $e->auth->user );
ok( $e->auth->user eq $e->session->{auth_data} );
ok( $e->auth->user_name );
ok( $e->user_name );
ok( $e->user_name eq 'foo' );
ok( $e->user_name eq $e->auth->user_name );
ok( $user->{email} );
ok( $user->{email} eq 'foo@email.domain' );
ok( $user->{nickname} );
ok( $user->{nickname} eq 'binbin' );
ok( $e->auth->user->{email} );
ok( $e->auth->user->{email} eq $user->{email} );
ok( $e->auth->user->{nickname} );
ok( $e->auth->user->{nickname} eq $user->{nickname} );
ok( $e->auth->logout );
ok( ! $e->session->{auth_data} );
ok( $e->auth->user );
ok( ! $e->auth->user->{email} );
ok( ! $e->user_name );
ok( ! $e->auth->user_name );

__DATA__
---
filename: etc/members.tsv
value: |
  foo	12345	1	foo@email.domain	binbin
  boo	23456	1	boo@email.domain	bonbon
  zuu	34567	0	boo@email.domain	zuuzuu
  hoo		1	hoo@email.domain	hoohoo


use Test::More qw/no_plan/;
use Egg::Helper::VirtualTest;

my $v= Egg::Helper::VirtualTest->new;
$v->prepare(
  controller=> { egg_includes=> [qw/ SessionKit::Auth::File /] },
  create_files=> [$v->yaml_load( join '', <DATA> )],
  config=> { plugin_session => {
    auth=> {
      data_path       => '<$e.root>/etc/members.tsv',
      constant        => [qw/uid psw active email nickname/],
      uid_db_field    => 'uid',
      psw_db_field    => 'psw',
      active_db_field => 'active',
    } } },
  );

ok my $e= $v->egg_pcomp_context;
ok my $auth= $e->auth;
isa_ok $auth, 'Egg::Plugin::SessionKit::Auth::File::handler';
isa_ok $auth, 'Egg::Plugin::SessionKit::Auth::handler';
isa_ok $auth, 'Egg::Plugin::SessionKit::Auth::Crypt::Plain';
can_ok $auth, qw/
  e config user user_name get_uid_param get_psw_param messages session errstr
  error_uid_undefined error_psw_undefined error_no_regist error_unactive
  error_discord_psw error_unset_psw error_secure_onry
  logout error errstr _get_login_argument psw_check restore
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


__DATA__
filename: etc/members.tsv
value: |
  foo	12345	1	foo@email.domain	binbin
  boo	23456	1	boo@email.domain	bonbon
  zuu	34567	0	boo@email.domain	zuuzuu
  hoo		1	hoo@email.domain	hoohoo

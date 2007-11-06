package Egg::Plugin::SessionKit::Auth;
#
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: Auth.pm 215 2007-11-06 23:17:11Z lushe $
#
use strict;
use warnings;
use base qw/Egg::Plugin::SessionKit/;

our $VERSION = '2.10';

=head1 NAME

Egg::Plugin::SessionKit::Auth - Authentication of session base.

=head1 SYNOPSIS

  use Egg qw/ SessionKit::Auth::File FillInForm /;
  
  __PACKAGE__->egg_startup(
    .......
    ...
  
    plugin_session=> {
      .......
      ...
      auth=> {
        psw_crypt_type => 'MD5',
        uid_param_name => '__uid',
        psw_param_name => '__psw',
        data_path      => '<$e.dir.etc>/members.txt',
        constant       => [qw/ uid psw active email nickname /],
        uid_db_field   => 'uid',
        psw_db_field   => 'psw',
        active_db_field=> 'active',
        messages=> {
          uid_undefined => 'Please input ID.',
          psw_undefined => 'Please input the password.',
          ...
          },
        },
      },
  
    plugin_fillinform=> {
      fill_password => 0,
      ignore_fields => [qw/ ticket /],
      },
  
    );

Example of authentication form. (L<Egg::View::Mason>)

  % if (my $error_message = $e->auth->errstr) {
    <div class="error"><% $error_message %></div>
  % }
  <form method="POST" action="/auth">
  <input type="hidden" name="ticket" value="<% $e->ticket_id(1) %>" />
  USER-ID : <input name="__uid" type="text" /> <br />
  PASSWORD: <input name="__psw" type="password" /> <br />
  <input type="submit" />
  </form>

Example of code.

  # The Auth object is acquired.
  my $auth= $e->auth;

  # The input of the login form is checked.
  my $user_id;
  if ($e->ticket_check and  $user_id= $e->auth->login) {
     $e->response->redirect('/members');
  } else {
     Login form is displayed again.
  }

  # The user who is logging it in now is checked.
  if (my $user_id= $e->user_name) {
    print "is login: $user_id";
  } else {
    print "It doesn't login.";
  }

  # Refer to user's data after it logs it in.
  my $user= $e->auth->user;
  print " NickName : $user->{nickname} \n";
  print " E-mail   : $user->{email} \n";

  # The data of an arbitrary user is acquired.
  if (my $user= $e->auth->restore($user_id)) {
    print " NickName : $user->{nickname} ";
  } else {
    print "There is no registration.";
  }

  # Logout.
  $e->auth->logout;

=head1 DESCRIPTION

It is a plugin that offers the attestation function of the session base.

* Please load the subclass into this plugin specifying it.

=head1 CONFIGURATION

Please define it in 'plugin_session->{auth}' with HASH.

=head2 uid_param_name

Name used for id field of login form.

Default is '__uid'.

=head2 psw_param_name

Name used for password field of login form.

Default is '__psw'.

=head2 uid_db_field

Name of column used to refer to ID of attestation data.

Default is 'uid'.

=head2 psw_db_field

Name of column used to refer to password of attestation data.

Default is 'psw'.

=head2 active_db_field

Name of column used to refer to effective flag of attestation data.

Default is 'active'.

=head2 psw_crypt_type

Module name to collate password code of attestation data by processing it.
This name is supplemented with 'Egg::Plugin::SessionKit::Auth::Crypt'.

Default is 'Plain'.

The following code processing modules are contained in the standard.

  L<Egg::Plugin::SessionKit::Auth::Crypt::Plain>,
  L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
  L<Egg::Plugin::SessionKit::Auth::Crypt::MD5>,

=head2 message => [MESSAGE_HASH]

The message of the login error can be set.

Please register the message with the following keys.

  uid_undefined  ..... Please input id.
  psw_undefined  ..... Please input the password.
  no_regist      ..... It is not registered.
  unactive       ..... It is not effective id.
  discord_psw    ..... Mistake of password.
  unset_psw      ..... The password is not set.
  secure_onry    ..... Please use it by the SSL connection.
  internal_error ..... The error not anticipated occurred.
  custom_message ..... Disagreement of ticket id.

=head2 ... etc.

Other settings are different according to the subclass that uses it.

The following subclasses are included in the standard.

  L<Egg::Plugin::SessionKit::Auth::File>,
  L<Egg::Plugin::SessionKit::Auth::DBI>,
  L<Egg::Plugin::SessionKit::Auth::DBIC>,

=cut

{
	my($handler, $aconf);
	sub _setup {
		my($e)= @_;
		$handler= $e->{session_auth_handler}
		   || die q{ Mistake of method of loading plugin. };
		my $cf= $e->config->{plugin_session} ||= {};
		$aconf= $cf->{auth} ||= {};
		##
		$aconf->{uid_param_name}  ||= '__uid';
		$aconf->{psw_param_name}  ||= '__psw';
		$aconf->{uid_db_field}    || die qq{ Please setup uid_db_field. };
		$aconf->{psw_db_field}    || die qq{ Please setup psw_db_field. };
		$aconf->{active_db_field} ||= 0;
		$aconf->{psw_crypt_type}  ||= 'Plain';
		##
		$handler->_startup($e, $aconf);
		$e->next::method;
	}
	sub auth { $_[0]->{sessionkit_auth} ||= $handler->new($_[0], $aconf) }
	sub reset_auth { $_[0]->{sessionkit_auth}= $handler->new($_[0], $aconf) }
  };

sub user_name { $_[0]->auth->user_name }
sub user_data { $_[0]->auth->user_data }

package Egg::Plugin::SessionKit::Auth::handler;
use strict;
use warnings;
use UNIVERSAL::require;
use base qw/Class::Accessor::Fast/;

__PACKAGE__->mk_accessors( qw/e config messages/ );

{
	no strict 'refs';  ## no critic
	no warnings 'redefine';
	for my $accessor (qw/ uid_undefined psw_undefined
	  no_regist unactive discord_psw unset_psw secure_onry /)
	  { *{"error_$accessor"}= sub { $_[0]->error($accessor) } }
  };

sub _startup {
	my($class, $e, $conf)= @_;
	no strict 'refs';  ## no critic
	no warnings 'redefine';
	*_https_check= $conf->{https_only}
	  ? sub { $_[0]->e->request->secure ? 1: 0 }: sub { 1 };
	my $pkg= "Egg::Plugin::SessionKit::Auth::Crypt::$conf->{psw_crypt_type}";
	unshift @{"${class}::ISA"}, $pkg;
	$pkg->require or die $@;
	@_;
}
sub new {
	my($class, $e, $conf)= @_;
	bless {  e => $e,
	  config   => $conf,
	  messages => ($conf->{messages} || {}),
	  errstr   => '',
	  uid_param_name  => $conf->{uid_param_name},
	  psw_param_name  => $conf->{psw_param_name},
	  uid_db_field    => $conf->{uid_db_field},
	  psw_db_field    => $conf->{psw_db_field},
	  active_db_field => $conf->{active_db_field},
	  }, $class;
}
sub session {
	$_[0]->e->session;
}
sub login {
	my $auth= shift;
	my $data= $auth->_get_login_argument(@_) || return 0;
	my $user= $auth->restore($data->[0])
	       || return $auth->error_no_regist;
	my $crypt= $user->{$auth->{psw_db_field}}
	       || return $auth->error_unset_psw;
	return $auth->error_unactive
	  if ($auth->{active_db_field} && ! $user->{$auth->{active_db_field}});
	return $auth->error_discord_psw unless $auth->psw_check(@$data, $crypt);
	my $uid= $user->{$auth->{uid_param_name}}= $user->{$auth->{uid_db_field}};
	$auth->user_data($user);
	$auth->e->debug_out("# + session auth : [$uid] - Login is succeed.");
	$user;
}
sub logout {
	my($auth)= @_;
	my $uid= $auth->user_name || return 1;
	$auth->session->clear;
	undef $auth->{user_name};
	$auth->e->debug_out("# + session auth : [$uid] - Logout OK.");
	return 1;
}
sub reset {
	my $auth= shift;
	my $user= shift || die q{ I want user data. };
	undef $auth->{user_name} if $auth->{user_name};
	if (my $uid= $user->{$auth->{uid_db_field}})
	   { $user->{$auth->{uid_param_name}}= $uid }
	$user;
}
sub user_name {
	$_[0]->{user_name} ||= $_[0]->user->{$_[0]->{uid_param_name}} || 0;
}

sub user_data_key_name { 'session_user_data' }

sub user {
	$_[0]->session->{ $_[0]->user_data_key_name } || {};
}
sub user_data {
	my $auth= shift;
	return $auth->session->{ $auth->user_data_key_name } || {} unless @_;
	$auth->session->{ $auth->user_data_key_name }= shift;
}

sub get_uid_param {
	$_[0]->e->request->params->{$_[0]->{uid_param_name}} || "";
}
sub get_psw_param {
	$_[0]->e->request->params->{$_[0]->{psw_param_name}} || "";
}
sub error {
	my $auth= shift;
	$auth->{errstr}= shift || 'internal_error';
	return 0;
}
*errstr= \&error_message;
sub error_message {
	my($auth)= @_;
	return $auth->{errstr}
	  ? ($auth->messages->{$auth->{errstr}} || $auth->{errstr}): 0;
}
sub _get_login_argument {
	my $auth= shift;
	$auth->_https_check || return $auth->error_secure_onry;
	my $uid= shift || $auth->get_uid_param
	      || return $auth->error_uid_undefined;
	my $psw= shift || $auth->get_psw_param
	      || return $auth->error_psw_undefined;
	s/\s+//g for ($uid, $psw);
	[$uid, $psw];
}

=head1 METHODS

=head2 auth

The handler object is returned.

=head2 user_name

It is an accessor to $e-E<gt>auth-E<gt>user_name.

=head2 user_data

Other data of the user under login is returned by the HASH reference.

=head2 reset_auth

It tries to make the object of the module of this now newly.

=head1 HANDLER METHODS

=head2 new

Constructor.

=head2 login ( [USER_ID], [LOGIN_PASSWD] )

The attestation data is returned with HASH when collating data and succeeding
in login.

When USER_ID is omitted, it acquires it from 'get_uid_param' method.

When LOGIN_PASSWD is omitted, it acquires it from 'get_psw_param' method.

* The message is set in 'error' method when failing in login.
  Please use 'errstr' method to refer.

  if (my $user_data= $e->auth->login) {
    .....
    ...

=head2 logout

It logs out if it is login.

=head2 user

User's registration data is returned by the HASH reference if it is logging it in.

  my $nickname= $e->auth->user->{nickname};

=head2 user_name

User ID that succeeds in the attestation is returned.

* 0 returns when failing in the attestation.

=head2 get_uid_param

User ID is returned from the form data based on 'uid_param_name'.

=head2 get_psw_param

The login password is returned from the form data based on 'psw_param_name'.

=head2 error ( [ERROR_MESSAGE] )

The error message is stored.

=head2 errstr

The error set by 'error' method is returned by the message for the screen output.

=head2 ... etc. ( error methods ),

  error_uid_undefined
  error_psw_undefined
  error_no_regist
  error_unactive
  error_discord_psw
  error_unset_psw

The above-mentioned method is contained as an accessor of 'error' method.
A prescribed error is set only by calling this method.
The above-mentioned method always returns 0.

=head1 WARNING

After the attestation succeeds, the acquired data is preserved in the session.
This data becomes invalid the session or is effective until being logged out.
Therefore, it is not in real data, and comes to come to refer to the data of
the session after login succeeds.

This method is high-speed treatable of a frequent attestation, and there is a
thing that the contradiction of data is generated when real data is corrected.

To our regret, the method of settlement is not being offered in a present 
version.

=head1 SEE ALSO

L<Egg::Plugin::SessionKit>,
L<Egg::Plugin::SessionKit::Auth::DBI>,
L<Egg::Plugin::SessionKit::Auth::DBIC>,
L<Egg::Plugin::SessionKit::Auth::File>,
L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
L<Egg::Plugin::SessionKit::Auth::Crypt::MD5>,
L<Egg::Plugin::SessionKit::Auth::Crypt::Plain>,
L<Egg::Model::DBI>,
L<Egg::Model::DBIC>,
L<Egg::Release>,

=head1 AUTHOR

Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2007 by Bee Flag, Corp.
       E<lt>L<http://egg.bomcity.com/>E<gt>, All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

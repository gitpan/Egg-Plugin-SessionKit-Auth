package Egg::Plugin::SessionKit::Auth;
#
# Copyright (C) 2007 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: Auth.pm 269 2007-03-02 09:28:00Z lushe $
#
use strict;
use warnings;
use base qw/Egg::Plugin::SessionKit/;

our $VERSION = '0.06';

sub setup {
	my($e)= @_;
	my $sconf= $e->config->{plugin_session} ||= {};
	my $aconf= $sconf->{auth} ||= {};
	$aconf->{uid_param_name} ||= '__uid';
	$aconf->{psw_param_name} ||= '__psw';
	$aconf->{psw_crypt_type} ||= 'Plain';
	my $handler= $e->global->{EGG_SESSION_AUTH_HANDLER}
	  || Egg::Error->throw(q{'EGG_SESSION_AUTH_HANDLER' flag is undefined.});
	$handler->startup($e, $aconf);
	$e->SUPER::setup;
}
sub auth {
	$_[0]->{auth} ||= do {
		my($e)= @_;
		my $handler= $e->global->{EGG_SESSION_AUTH_HANDLER};
		$handler->new($e);
	  };
}
sub user_name { $_[0]->auth->user_name }

package Egg::Plugin::SessionKit::Auth::handler;
use strict;
use warnings;
use NEXT;
use base qw/Class::Accessor::Fast/;

__PACKAGE__->mk_accessors( qw/e config messages session errstr/ );

{
	no strict 'refs';  ## no critic
	no warnings 'redefine';
	for my $accessor
	(qw/uid_undefined psw_undefined
	  no_regist unactive discord_psw unset_psw secure_onry/)
	  { *{__PACKAGE__."::error_$accessor"}= sub { $_[0]->error($accessor) } }
  };

sub startup {
	my($class, $e, $aconf)= @_;
	tied(%{$e->global})->global_overwrite(
	  'EGG_SESSION_AUTH_HTTPS_CHECK' => (
	    $aconf->{https_only}
	      ? sub { $_[0]->e->request->secure ? 1: 0 }: sub { 1 }
	    ),
	  );
	my $crypt=
	  "Egg::Plugin::SessionKit::Auth::Crypt::$aconf->{psw_crypt_type}";
	$crypt->require or Egg::Error->throw($@);
	no strict 'refs';  ## no critic
	unshift @{__PACKAGE__.'::ISA'}, $crypt;
	$class->NEXT::startup($e, $aconf);
}
sub new {
	my($class, $e)= @_;
	my $aconf= $e->config->{plugin_session}{auth};
	my %messages= $aconf->{messages} ? %{$aconf->{messages}}: ();
	bless {
	  e=> $e, errstr=> '', config=> $aconf,
	  session=> $e->session, messages=> \%messages,
	  uid_param_name=> $aconf->{uid_param_name},
	  psw_param_name=> $aconf->{psw_param_name},
	  }, $class;
}
sub user
  { $_[0]->session->{auth_data} || {} }
sub user_name
  { $_[0]->{user_name} ||= $_[0]->user->{$_[0]->{uid_param_name}} || 0 }
sub get_uid_param
  { $_[0]->e->request->params->{$_[0]->{uid_param_name}} || "" }
sub get_psw_param
  { $_[0]->e->request->params->{$_[0]->{psw_param_name}} || "" }

sub get_login_argument {
	my $auth= shift;
	$auth->e->global->{EGG_SESSION_AUTH_HTTPS_CHECK}->()
	  || return $auth->error_secure_onry;
	my $uid = shift
	  || $auth->get_uid_param || return $auth->error_uid_undefined;
	my $psw = shift
	  || $auth->get_psw_param || return $auth->error_psw_undefined;
	s/\s+//g for ($uid, $psw);
	($auth, $uid, $psw);
}
sub logout {
	my($auth)= @_;
	return 1 unless $auth->user_name;
	tied(%{$auth->session})->clear;
	undef($auth->{user_name});
	$auth->e->debug_out("# + session auth : Logout OK.");
	return 1;
}
sub error {
	my $auth= shift;
	$auth->{errstr}= shift || 'internal_error';
	return 0;
}
sub errstr {
	my($auth)= @_;
	return $auth->{errstr}
	  ? ($auth->messages->{$auth->{errstr}} || $auth->{errstr}): 0;
}

1;

__END__

=head1 NAME

Egg::Plugin::SessionKit::Auth - The authentication function is offered by using the session.

=head1 SYNOPSIS

  package MYPROJECT;
  use strict;
  use Egg qw/Plugin::SessionKit::Auth::DBI/;

Configuration.

  plugin_session=> {
    ...
    ...
    auth=> {
      uid_param_name=> '__uid',
      psw_param_name=> '__psw',
      psw_crypt_type=> 'Plain',
      messages=> {
        uid_undefined => 'Please input user id.',
        psw_undefined => 'Please input password.',
        no_regist     => 'There is no registration.',
        unactive      => 'It is an invalid member.',
        discord_psw   => 'Mistake of password.',
        unset_psw     => 'The password is not registered.',
        secure_onry   => 'Please access it with https.',
        internal_error=> 'Internal error.',
        custom_message=> 'The ticket is a disagreement.',
        },
      },
    },

Example of authentication form.  (For Mason)

  % if (my $errmsg= $e->auth->errstr) {
    <div class="error"><% $errmsg %></div>
  % }
  <form method="POST" action="/auth">
  <input type="hidden" name="ticket" value="<% $e->ticket_id(1) %>" />
  USER-ID : <input type="text" name="__uid" /> <br />
  PASSWORD: <input type="text" name="__psw" /> <br />
  <input type="submit" />
  </form>

Example of code.

  if ($e->request->is_post && $e->ticket_check) {
  
    if ($e->auth->login) {
      print $e->user_name . " logged it in.";
    } else {
      print "Login is refused : ". $e->auth->errstr;
    }
  
  } else {
    $e->auth->error('custom_message');
    print "Stop: ". $e->auth->errstr;
  }

* Please see the document of Egg::Plugin::SessionKit about the part of the ticket.

* After it logs it in, the state can be checked by confirming $e->auth->user_name.

=head1 DESCRIPTION

The data of the member who succeeds in login is preserved in the session, and the state 
 is continued.

To move this module, should by way of the module that handles the treatment of the 
 authentication data.

=head1 CONFIGURATION

plugin_session->{auth} becomes setup of this module.

=head2 uid_param_name

id name form for authentication.

B<Default is '__uid'>

=head2 psw_param_name

password name form for authentication.

B<Default is '__psw'>

=head2 psw_crypt_type

The module name to process the code of the password used for the authentication check is specified.
It is necessary to specify the module that the subordinate of Egg::Plugin::SessionKit::Auth::Crypt has.

B<Default is 'Plain'>

=head2 secure_only

The authentication is made to function only at the SSL communication.

B<Default is none.>

=head2 messages

A real message of the key word returned when the error occurs can be set.
When this setting doesn't exist, the key word is returned as it is.

B<Default is none.>

It is a key word list.

  uid_undefined  : id cannot be acquired from the parameter.
  psw_undefined  : password cannot be acquired from the parameter.
  no_regist      : When there is no registration.
  unactive       : When it is an invalid member.
  discord_psw    : When the password is wrong.
  unset_psw      : When there is no password that should be collated.
  secure_only    : If it is not https, it is not possible to login.
  internal_error : When the error not anticipated occurs.

=head1 METHODS

=head2 $e->auth

The object of this module is returned.

=head2 $e->auth->login([UID], [PASSWORD]);

The authentication check is done.

When [UID] and [PASSWORD] are omitted, the value is acquired from $e->request->params.

It comes to be able to acquire id logging it in $e->auth->user_name when succeeding in login.

=head2 $e->auth->logout

The logout processing is done.
The user data of the session is deleted.

$e->auth->user_name comes to return false by this.

=head2 $e->auth->user_name  or $e->user_name

id is returned when logging it in.

=head2 $e->auth->user

Member's data under login can be referred to.
It is possible to refer if there are data other than id and password.

Empty HASH is restored even if it doesn't log it in.

=head2 $e->errstr

The cause of failure is set when failing in $e->auth->login.

=head2 $e->get_uid_param

The parameter that relates to the name set to 'uid_param_name' is returned.

=head2 $e->get_psw_param

The parameter that relates to the name set to 'psw_param_name' is returned.

=head2 error([ERROR_KEYWORD]);

When failing in $e->auth->login, the key word is set by this function.
This method need not be called directly usually.

The method for the reduction of the mistake when the key word is set is prepared.
If this method is used, the mistake is reported at once.

  error_uid_undefined
  error_psw_undefined
  error_no_regist
  error_unactive
  error_discord_psw
  error_unset_psw

=head1 SEE ALSO

L<Egg::SessionKit::Auth>,
L<Egg::SessionKit::Auth::DBI>,
L<Egg::SessionKit::Auth::File>,
L<Egg::SessionKit::Auth::Crypt::CBC>,
L<Egg::SessionKit::Auth::Crypt::Plain>,
L<Egg::Release>,

=head1 AUTHOR

Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2007 by Bee Flag, Corp. E<lt>L<http://egg.bomcity.com/>E<gt>, All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut


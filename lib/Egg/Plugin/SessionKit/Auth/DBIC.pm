package Egg::Plugin::SessionKit::Auth::DBIC;
#
# Copyright (C) 2007 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: DBIC.pm 271 2007-03-02 14:03:41Z lushe $
#
use strict;
use base qw/Egg::Plugin::SessionKit::Auth/;

our $VERSION = '0.01';

sub setup {
	my($e)= @_;
	my $sconf= $e->config->{plugin_session} ||= {};
	my $aconf= $sconf->{auth} ||= {};
	$aconf->{model_name}
	  || Egg::Error->throw(qq{ I want setup 'model_name'. });
	$aconf->{model_name}=~m{^[A-Za-z]+\:[A-Za-z0-9_]+$}
	  || Egg::Error->throw(qq{ Bad format as model name. });
	$e->is_model($aconf->{model_name})
	  || Egg::Error->throw(qq{ '$aconf->{model_name}' model is not found. });
	$aconf->{uid_db_field}
	  || Egg::Error->throw(q/Please setup 'uid_db_field'./);
	$aconf->{psw_db_field}
	  || Egg::Error->throw(q/Please setup 'psw_db_field'./);
	$aconf->{active_db_field} ||= 0;
	$aconf->{uid_db_search_field} ||= $aconf->{uid_db_field};
	$e->global->{EGG_SESSION_AUTH_RESULT_CODE} ||=
	  $aconf->{search_attr} ? sub {
		my $hash= shift || return 0;
		my %user;
		while (my($key, $value)= each %$hash) {
			if (ref($value) eq 'HASH') {
				@user{keys %$value}= values %$value;
			} else {
				$user{$key}= $value;
			}
		}
		return \%user;
	  }: do {
		$aconf->{search_attr}= {};
		sub { @_  };
	  };
	$e->global->{EGG_SESSION_AUTH_HANDLER} ||= __PACKAGE__.'::handler';
	$e->SUPER::setup;
}

package Egg::Plugin::SessionKit::Auth::DBIC::handler;
use strict;
use base qw/Egg::Plugin::SessionKit::Auth::handler/;
use DBIx::Class::ResultClass::HashRefInflator;

sub login {
	my($auth, $uid, $psw)= shift->get_login_argument(@_);
	return 0 unless ($uid && $psw);
	my $c= $auth->e->config->{plugin_session}{auth};
	my $user= $auth->restore($uid) || return $auth->error_no_regist;
	my $crypt= $user->{$c->{psw_db_field}} || return $auth->error_unset_psw;
	return $auth->error_unactive
	  if ($c->{active_db_field} && ! $user->{$c->{active_db_field}});
	return $auth->error_discord_psw unless $auth->psw_check($uid, $psw, $crypt);
	$user->{$auth->{uid_param_name}}= $user->{$c->{uid_db_field}};
	$auth->session->{auth_data}= $user;
	$auth->e->debug_out("# + session auth : Login is succeed.");
	return $user;
}
sub restore {
	my $auth= shift;
	my $uid = shift || Egg::Error->throw(q/I want 'uid'/);
	my $c= $auth->e->config->{plugin_session}{auth};
	my $uname= shift || $c->{uid_db_field};
	my $model= $auth->e->model($c->{model_name})
	  || Egg::Error->throw(qq{ '$c->{model_name}' model is not found. });
	my $result= $model->search
	  ({ $c->{uid_db_search_field} => $uid }, $c->{search_attr});
	$result->result_class('DBIx::Class::ResultClass::HashRefInflator');
	$auth->e->global->{EGG_SESSION_AUTH_RESULT_CODE}->($result->first);
}

1;

__END__

=head1 NAME

Egg::Plugin::SessionKit::Auth::DBI - Session attestation plugin that uses DBIx::Class.

=head1 SYNOPSIS

  package MYPROJECT;
  use strict;
  use Egg qw/Plugin::SessionKit::Auth::DBIC/;

Configuration.

  plugin_session=> {
    ...
    ...
    auth => {
      ...
      ...
      model_name      => 'myapp:fooo',
      uid_db_field    => 'user_id',
      psw_db_field    => 'password',
      active_db_field => 'active',
      },
    },

Example of code.

  my $auth= $e->auth;  # Auth object is acquired.
  
  if ($auth->user_name) {
  	print "Login is done.";
  
  	my $email= $auth->user->{email} || "";
  
  } else {
  	print "It doesn't login.";
  }

=head1 DESCRIPTION

* DBIx::Class::ResultClass::HashRefInflator is used. 
  This module has not been included before DBIx-Class-0.07999_02.
  DBIx-Class under use is the latest or confirm it, please.

Attestation information is acquired by handling the model whom L<Egg::Model::DBIC>
generated. The name of the model is specified by 'model_name'.

And, the field name to refer to ID and the password is specified for 'uid_db_field'
and 'psw_db_field'.

Moreover, if the data that doesn't want to be attested even if done is included,
registration specifies the field name to judge it for 'active_db_field'.

* If this field value is false, it doesn't attest it.

It becomes necessary minimum set above in the case of data for the attestation
of one table composition.

When the relation is done with two or more tables, 'search_attr' for the addition
parameters such as 'uid_db_search_field' to use it further by SQL statement and
JOIN is set.

For instance, it becomes the following.

  plugin_session=> {
    auth => {
      model_name          => 'myapp:members',
      uid_db_field        => 'uid',
      psw_db_field        => 'psw',
      uid_db_search_field => 'me.uid',
      search_attr         => { join=> [qw/ profiles /] },
      },
    },

Search is done to a specified model by the following syntaxes in this.

  my $result= $auth->e->model('myapp:members')->search(
    { 'me.uid' => $id },
    { join=> [qw/ profiles /] },
    );

DBIx::Class throws out following SQL to the data base by this syntax.

  SELECT me.uid, me.psw, me.regist_date, profiles.email, profiles.nickname
  FROM members me LEFT JOIN profiles profiles ON ( profiles.uid = me.uid )
  WHERE ( me.uid = ? )

* SQL syntax generated with the content given to the structure and search_attr
  of Schema is changed.

It comes to be able to refer to the acquired data by 'user' method by being
preserved in 'auth_data' of the session after it attests it.

  my $nickname= $auth->user->{nickname};

=head1 CONFIGURATION

=head2 model_name

Name of model used for attestation.

=head2 uid_db_field

Name of id field.

B<Default is none.>, Undefined is an error.

=head2 psw_db_field

Name of password field.

B<Default is none.>, Undefined is an error.

=head2 active_db_field

Field name to judge whether acquired data is effective.
This is evaluated only when defined.

For instance, if this field is undefined even if succeeding in the acquisition of data because 
of the inquiry of $e->auth->login, false is returned.

B<Default is none.>

=head2 uid_db_search_field

Name of ID field to pick up data by SQL.

B<Default is none.>,

=head2 search_attr

For retrieval parameter. It defines it by the HASH reference.

B<Default is none.>,

=head1 METHODS

=head2 $e->auth->login

The login check is done.

Please see L<Egg::Plugin::SessionKit::Auth> in detail.

=head2 $e->auth->restore([USER_ID]);

The attestation data corresponding to specified ID is returned by the HASH 
reference.

=head1 BUGS

When wrong 'restore_sql' was set, it suffered from the freezed symptom.
The current cause of the place cannot specify this error.

=head1 SEE ALSO

L<Egg::SessionKit>,
L<Egg::SessionKit::Auth>,
L<Egg::Release>,

=head1 AUTHOR

Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2007 by Bee Flag, Corp. E<lt>L<http://egg.bomcity.com/>E<gt>, All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

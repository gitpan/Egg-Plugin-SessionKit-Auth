package Egg::Plugin::SessionKit::Auth::DBI;
#
# Copyright (C) 2007 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: DBI.pm 269 2007-03-02 09:28:00Z lushe $
#
use strict;
use base qw/Egg::Plugin::SessionKit::Auth/;

our $VERSION = '0.02';

sub setup {
	my($e)= @_;
	$e->isa('Egg::Plugin::DBI::CommitOK')
	  || Egg::Error->throw(q/Please build in Egg::Plugin::DBI::CommitOK./);
	my $sconf= $e->config->{plugin_session} ||= {};
	my $aconf= $sconf->{auth} ||= {};
	$aconf->{dbname} ||= 'members';
	$aconf->{uid_db_field}
	  || Egg::Error->throw(q/Please setup uid_db_field./);
	$aconf->{psw_db_field}
	  || Egg::Error->throw(q/Please setup psw_db_field./);
	$aconf->{restore_sql}
	  ||= q{ SELECT * FROM <# dbname #> WHERE <# uid_db_field #> = ? };
	$aconf->{active_db_field} ||= 0;
	$aconf->{restore_sql}
	  =~s{<\#\s+(.+?)\s+\#>} [ $aconf->{$1} ? $aconf->{$1}: "" ]ge;
	$e->global->{EGG_SESSION_AUTH_HANDLER} ||= __PACKAGE__.'::handler';
	$e->SUPER::setup;
}

package Egg::Plugin::SessionKit::Auth::DBI::handler;
use strict;
use base qw/Egg::Plugin::SessionKit::Auth::handler/;

my @move_items= qw/uid_db_field psw_db_field active_db_field restore_sql/;

sub new {
	my $auth= shift->SUPER::new(@_);
	@{$auth}{@move_items}= @{$auth->config}{@move_items};
	$auth;
}
sub login {
	my($auth, $uid, $psw)= shift->get_login_argument(@_);
	return 0 unless ($uid && $psw);
	my $user= $auth->restore($uid) || return $auth->error_no_regist;
	my $crypt= $user->{$auth->{psw_db_field}} || return $auth->error_unset_psw;
	return $auth->error_unactive
	  if ($auth->{active_db_field} && ! $user->{$auth->{active_db_field}});
	return $auth->error_discord_psw unless $auth->psw_check($uid, $psw, $crypt);
	$user->{$auth->{uid_param_name}}= $user->{$auth->{uid_db_field}};
	$auth->session->{auth_data}= $user;
	$auth->e->debug_out("# + session auth : Login is succeed.");
	return $user;
}
sub restore {
	my $auth = shift;
	my $uid  = shift || Egg::Error->throw(q/I want 'uid'/);
	my $uname= shift || $auth->{uid_db_field};
	my $sql  = shift || $auth->{restore_sql};
	my %bind;
	my $sth= $auth->e->dbh->prepare($sql);
	$sth->execute($uid);
	$sth->bind_columns(\(@bind{map{$_}@{$sth->{NAME_lc}}}));
	$sth->fetch; $sth->finish;
	return 0 unless $bind{$uname};
	$auth->e->debug_out("# + session auth : restore member is succeed.");
	\%bind;
}

1;

__END__

=head1 NAME

Egg::Plugin::SessionKit::Auth::DBI - Data is acquired and authentication from the data base.

=head1 SYNOPSIS

  package MYPROJECT;
  use strict;
  use Egg qw/Plugin::SessionKit::Auth::DBI/;

Configuration.

  plugin_session=> {
    ...
    ...
    auth=> {
      ...
      ...
      dbname         => 'member_data',
      uid_db_field   => 'user_id',
      psw_db_field   => 'password',
      active_db_field=> 'active',
      restore_sql    => 'SELECT * FROM <# dbname #> a JOIN profile b'
                     . ' ON a.<# uid_db_field #> = b.<# uid_db_field #>'
                     . ' WHERE a.<# uid_db_field #> = ? ',
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

Data is acquired and attested by SQL set to 'restore_sql'.

E<lt># configuration name #E<gt> in 'restore_sql' can be substituted by other set values.

The data acquired here can be referred to through $e->auth->user when login succeeds.

=head1 CONFIGURATION

=head2 dbname

Table name of authentication data.

B<Default is 'members'>

=head2 uid_db_field

Name of id field

B<Default is none.>, Undefined is an error.

=head2 psw_db_field

B<Default is none.>, Undefined is an error.

=head2 active_db_field

Field name to judge whether acquired data is effective.
This is evaluated only when defined.

For instance, if this field is undefined even if succeeding in the acquisition of data because 
of the inquiry of $e->auth->login, false is returned.

B<Default is none.>

=head2 restore_sql

SQL sentence to acquire attestation data.

Substitution that uses E<lt># configuration name #E<gt> can be done.

I think a little complex SELECT sentence to be treatable mostly well.
However, it should be SQL sentence that at least acquires ID and password.

B<Default is> 'SELECT * FROM <# dbname #> WHERE <# uid_db_field #> = ?'

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

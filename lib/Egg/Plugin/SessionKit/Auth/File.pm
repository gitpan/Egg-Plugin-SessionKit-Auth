package Egg::Plugin::SessionKit::Auth::File;
#
# Copyright (C) 2007 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: File.pm 70 2007-03-26 02:29:02Z lushe $
#
use strict;
use base qw/Egg::Plugin::SessionKit::Auth/;

our $VERSION = '0.04';

sub setup {
	my($e)= @_;
	my $sconf= $e->config->{plugin_session} ||= {};
	my $aconf= $sconf->{auth} ||= {};
	$aconf->{constant}
	  || Egg::Error->throw(q/Please setup constant./);
	ref($aconf->{constant}) eq 'ARRAY'
	  || Egg::Error->throw(q/Please set constant by the ARRAY reference./);
	$aconf->{data_path} || Egg::Error->throw(q/Please setup data_path./);
	-f $aconf->{data_path}
	  || Egg::Error->throw(qq/File not found : $aconf->{data_path}/);
	$aconf->{uid_db_field}
	  || Egg::Error->throw(q/Please setup uid_db_field./);
	$aconf->{psw_db_field}
	  || Egg::Error->throw(q/Please setup psw_db_field./);
	$aconf->{separator} ||= "\t";
	$e->global->{EGG_SESSION_AUTH_HANDLER} ||= __PACKAGE__.'::handler';
	$e->SUPER::setup;
}

package Egg::Plugin::SessionKit::Auth::File::handler;
use strict;
use FileHandle;
use base qw/Egg::Plugin::SessionKit::Auth::handler/;

my @move_items= qw/constant uid_db_field psw_db_field data_path separator/;

sub new {
	my $auth= shift->SUPER::new(@_);
	@{$auth}{@move_items}= @{$auth->config}{@move_items};
	$auth->{active_db_field}= $auth->config->{active_db_field} || 0;
	$auth;
}
sub login {
	my($auth, $uid, $psw)= shift->get_login_argument(@_);
	return 0 unless ($uid && $psw);
	my $user = $auth->restore($uid)
	  || return $auth->error_no_regist;
	my $crypt= $user->{$auth->{psw_db_field}}
	  || return $auth->error_unset_psw;
	return $auth->error_unactive
	  if ($auth->{active_db_field} && ! $user->{$auth->{active_db_field}});
	return $auth->error_discord_psw
	  unless $auth->psw_check($uid, $psw, $crypt);
	$user->{$auth->{uid_param_name}}= $user->{$auth->{uid_db_field}};
	$auth->session->{auth_data}= $user;
	$auth->e->debug_out("# + session auth : Login is succeed.");
	return $user;
}
sub restore {
	my $auth = shift;
	my $uid  = shift || Egg::Error->throw(q/I want 'uid'/);
	my $uname= shift || $auth->{uid_db_field};
	my $separ= shift || $auth->{separator};
	my $const= shift || $auth->{constant};
	my $fh= FileHandle->new($auth->{data_path}) || Egg::Error->throw($!);
	while (my $line= $fh->getline) {
		chomp($line);
		my %user;
		@user{@$const}= split /$separ/, $line;
		if ($user{$uname} && $user{$uname} eq $uid) {
			$auth->e->debug_out("# + session auth : restore member is succeed.");
			return \%user;
		}
	}
	$fh->close;
	return 0;
}

1;

__END__

=head1 NAME

Egg::Plugin::SessionKit::Auth::File - It authentication it based on the data of the file.

=head1 SYNOPSIS

  package MYPROJECT;
  use strict;
  use Egg qw/Plugin::SessionKit::Auth::File/;

Configuration.

  plugin_session=> {
    ...
    ...
    auth=> {
      ...
      ...
      data_path      => '/path/to/user_data',
      uid_db_field   => 'user_id',
      psw_db_field   => 'password',
      active_db_field=> 'active',
      separator      => ':',
      constant=> [qw/user_id password active email nickname ... etc. /],
    },
  },

=head1 DESCRIPTION

It authentication it based on the data managed with the file.

For instance, data structures of the following TSV types are assumed.

  foo	12345	1	foo@domain	foofoo
  baa	12345	1	baa@domain	baabaa
  zuu	12345	0	zuu@domain	zuuzuu

=head1 CONFIGURATION

=head2 data_path

Path of data file.

B<Default is none.>,  Undefined is an error.

=head2 separator

Delimiter of each data.

B<Default is "\t">

=head2 constant

ARRAY divided by 'separator' ties by the name.

  foo	12345	1	foo@domain	foofoo

  constant=> [qw/uid psw active email nickname/],

This is developed as follows.

  $user->{uid}       -> foo
  $user->{psw}       -> 12345
  $user->{active}    -> 1
  $user->{email}     -> foo@domain
  $user->{nickname}  -> foofoo

B<Default is none.>,  Undefined is an error.

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

=head1 METHODS

=head2 $e->auth->login

The login check is done.

Please see L<Egg::Plugin::SessionKit::Auth> in detail.

=head2 $e->auth->restore([USER_ID]);

The attestation data corresponding to specified ID is returned by the HASH 
reference.

=head2 setup

It is a method for the start preparation that is called from the controller of 
the project. * Do not call it from the application.

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

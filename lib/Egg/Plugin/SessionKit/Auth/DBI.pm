package Egg::Plugin::SessionKit::Auth::DBI;
#
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: DBI.pm 151 2007-05-16 22:51:44Z lushe $
#
use strict;
use warnings;
use base qw/Egg::Plugin::SessionKit::Auth/;

our $VERSION = '2.01';

=head1 NAME

Egg::Plugin::SessionKit::Auth::DBI - It attests it by DBI.

=head1 SYNOPSIS

  use Egg qw/ SessionKit::Auth::DBI /;
  
  __PACKAGE__->egg_startup(
    .......
    ...
    MODEL => [ [ DBI => {
      .......
      ...
      } ] ],
  
    plugin_session=> {
      .......
      ...
      auth => {
        dbname      => 'members',
        restore_sql => q{ SELECT * FROM <$e.dbname> a }
                    .  q{ LEFT OUTER JOIN profile b ON a.uid = b.uid }
                    .  q{ WHERE a.uid = ? },
        .......
        ...
        },
      },
  
    );

=head1 DESCRIPTION

It attests it by L<Egg::Model::DBI>.

It collates data from the following tables and it attests it.

  CREATE TABLE members (
    id       int2      primary key,
    uid      varchar,
    psw      varchar,
    active   int2,
    email    varchar,
    nickname varchar
    );

* The above-mentioned is one example until becoming empty.
  If ID and the password that becomes a retrieval key become complete, it is
  not necessary to learn it from the above-mentioned.
  As for other data, the thing that uses 'user' method after login succeeds
  and refers becomes possible.

Please refer to the document of L<Egg::Plugin::SessionKit::Auth>.

=head1 CONFIGURATION

=head2 dbname

Table name of attestation data.

Default is 'members'.

=head2 restore_sql

SQL sentence to retrieve data.

* $e-E<gt>replace is done.

Default is ' SELECT * FROM <$e.dbname> WHERE <$e.uid_db_field> = ? '.

=cut
sub _setup {
	my($e)= @_;
	$e->{session_auth_handler} ||= __PACKAGE__.'::handler';
	$e->SUPER::_setup;
}
sub _finalize {
	my($e)= @_;
	$e->{session_auth_sth}->finish if $e->{session_auth_sth};
	$e->next::method;
}
sub _finalize_error {
	my($e)= @_;
	$e->{session_auth_sth}->finish if $e->{session_auth_sth};
	$e->next::method;
}

package Egg::Plugin::SessionKit::Auth::DBI::handler;
use strict;
use warnings;
use Carp qw/croak/;
use base qw/Egg::Plugin::SessionKit::Auth::handler/;

=head1 METHODS

=cut
sub _startup {
	my($class, $e, $conf)= @_;
	$class->_initialize($conf);
	$conf->{dbname} ||= 'members';
	my $sql= $conf->{restore_sql}
	     ||= q{ SELECT * FROM <$e.dbname> WHERE <$e.uid_db_field> = ? };
	$e->replace($conf, \$sql);
	no warnings 'redefine';
	*_prepare= sub {
		my($auth)= @_;
		$auth->{dbh} ||= $auth->e->model('DBI')->dbh;
		$auth->e->{session_auth_sth} ||= $auth->{dbh}->prepare($sql);
	  };
	$class->SUPER::_startup($e, $conf);
}

=head2 restore ( [USER_ID] )

Data is returned by the HASH reference when found looking for USER_ID from the 
attestation data.  0 returns when not found.

=cut
sub restore {
	my $auth= shift;
	my $uid = shift || croak q{ I want 'uid' };
	my %bind;
	my $sth= $auth->_prepare;
	$sth->execute($uid);
	$sth->bind_columns(\(@bind{map{$_}@{$sth->{NAME_lc}}}));
	$sth->fetch;
	$bind{$auth->{uid_db_field}} ? \%bind: 0;
}

=head1 SEE ALSO

L<Egg::Plugin::SessionKit>,
L<Egg::Plugin::SessionKit::Auth>,
L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
L<Egg::Plugin::SessionKit::Auth::Crypt::MD5>,
L<Egg::Plugin::SessionKit::Auth::Crypt::Plain>,
L<Egg::Model::DBI>,
L<Egg::Release>,

=head1 AUTHOR

Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>

=head1 COPYRIGHT

Copyright (C) 2007 by Bee Flag, Corp. E<lt>L<http://egg.bomcity.com/>E<gt>, All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

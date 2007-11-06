package Egg::Plugin::SessionKit::Auth::DBIC;
#
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: DBIC.pm 215 2007-11-06 23:17:11Z lushe $
#
use strict;
use warnings;
use base qw/Egg::Plugin::SessionKit::Auth/;

our $VERSION = '2.01';

=head1 NAME

Egg::Plugin::SessionKit::Auth::DBIC - It attests it by DBIC.

=head1 SYNOPSIS

  use Egg qw/ SessionKit::Auth::DBI /;
  
  __PACKAGE__->egg_startup(
    .......
    ...
    MODEL => [ [ DBIC => {} ] ],
  
    plugin_session=> {
      .......
      ...
      auth => {
        model_name => 'myschema:members',
        uid_db_search_field => 'uid',
        .......
        ...
        },
      },
  
    );

=head1 DESCRIPTION

It attests it by L<Egg::Model::DBIC>.

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
  and refers  becomes possible.

* L<DBIx::Class::ResultClass::HashRefInflator> is used.
  As for this module, the package included even if it tries to install it 
  specifying L<DBIx::Class> from the CPAN module seems not to be downloaded.
  The included package is L<http://search.cpan.org/dist/DBIx-Class-0.07999_02/>
  Please refer to.

=head1 CONFIGURATION

=head2 model_name

Name of Model acquired from L<Egg::Model::DBIC>.

There is no default. Please specify it.

=head2 uid_db_search_field

Name of column used for retrieval.

For instance, please specify it when the identifier is necessary etc.

  uid_db_search_field => 'a.uid',

As for default, the value of 'uid_db_field' is copied.

=head2 search_attr

The second argument passed to 'Search' method of Model can be set.

* The retrieval is done by the following codes.

  my $result= $model->search({ $uid_db_search_field => $uid }, $search_attr);

=cut
sub _setup {
	my($e)= @_;
	$e->{session_auth_handler} ||= __PACKAGE__.'::handler';
	$e->SUPER::_setup;
}

package Egg::Plugin::SessionKit::Auth::DBIC::handler;
use strict;
use warnings;
use Carp qw/croak/;
use base qw/Egg::Plugin::SessionKit::Auth::handler/;
use DBIx::Class::ResultClass::HashRefInflator;

=head1 METHODS

=cut
sub _startup {
	my($class, $e, $conf)= @_;
	my $model_name= $conf->{model_name}
	               || die "I want setup 'model_name'.";
	$model_name=~m{^[A-Za-z]+\:[A-Za-z0-9_]+$}
	               || die "Bad format as model name.";
	$e->is_model($model_name)
	               || die "'$model_name' model is not found.";
	my $field= $conf->{uid_db_search_field} || $conf->{uid_db_field};

	my $attr= $conf->{search_attr} || {};

	no warnings 'redefine';
	*_search= sub {
		my($auth, $uid)= @_;
		$auth->{model} ||= $auth->e->model($model_name);
		my $result= $auth->{model}->search({ $field => $uid }, $attr);
		$result->result_class('DBIx::Class::ResultClass::HashRefInflator');
		$result->first;
	  };

	$class->SUPER::_startup($e, $conf);
}

=head2 restore ( [USER_ID] )

Data is returned by the HASH reference when found looking for USER_ID from the 
attestation data.  0 returns when not found.

=cut
sub restore {
	my $auth= shift;
	my $uid = shift || croak q{ I want 'uid'. };
	$auth->_search($uid);
}

=head1 SEE ALSO

L<Egg::Plugin::SessionKit>,
L<Egg::Plugin::SessionKit::Auth>,
L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
L<Egg::Plugin::SessionKit::Auth::Crypt::MD5>,
L<Egg::Plugin::SessionKit::Auth::Crypt::Plain>,
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

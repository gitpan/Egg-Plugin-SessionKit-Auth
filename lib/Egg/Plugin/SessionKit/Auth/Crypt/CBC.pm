package Egg::Plugin::SessionKit::Auth::Crypt::CBC;
#
# Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>
#
# $Id: CBC.pm 146 2007-05-13 18:50:08Z lushe $
#

=head1 NAME

Egg::Plugin::SessionKit::Auth::Crypt::CBC - Password is collated by Crypt::CBC.

=head1 SYNOPSIS

  use Egg qw/ Crypt::CBC SessionKit::Auth::File /;
    .......
    ...
    plugin_session=> {
      psw_crypt_type => 'CBC',
      .......
      ...
      },

=head1 DESCRIPTION

The password is collated by L<Egg::Plugin::Crypt::CBC>.

* Please load L<Egg::Plugin::Crypt::CBC>.

=cut
use strict;
use warnings;

our $VERSION= '2.00';

=head1 METHODS

=cut
sub _startup {
	my($class, $e, $conf)= @_;
	$e->isa('Egg::Plugin::Crypt::CBC')
	   || die q{ Please build in Egg::Plugin::Crypt::CBC. };
	$class->next::method($e, $conf);
}

=head2 psw_check ( [USER_ID], [PLAIN_PASSWD], [CRYPT_PASSWD] )

The password is collated.

=cut
sub psw_check {
	my($auth, $uid, $psw, $crypt)= @_;
	my $plain= $auth->e->cbc_decode($crypt) || return 0;
	$psw eq $plain ? 1: 0;
}

=head1 SEE ALSO

L<Egg::Plugin::SessionKit::Auth>,
L<Egg::Plugin::SessionKit::Auth::Crypt::MD5>,
L<Egg::Plugin::SessionKit::Auth::Crypt::Plain>,
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

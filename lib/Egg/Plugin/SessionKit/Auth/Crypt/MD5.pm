package Egg::Plugin::SessionKit::Auth::Crypt::MD5;
#
# Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>
#
# $Id: MD5.pm 146 2007-05-13 18:50:08Z lushe $
#

=head1 NAME

Egg::Plugin::SessionKit::Auth::Crypt::MD5 - Password is collated by Digest::MD5.

=head1 SYNOPSIS

  use Egg qw/ SessionKit::Auth::File /;
    .......
    ...
    plugin_session=> {
      psw_crypt_type => 'MD5',
      .......
      ...
      },

=head1 DESCRIPTION

The password is collated by L<Digest::MD5>.

=cut
use strict;
use warnings;
use Digest::MD5;

our $VERSION= '2.00';

=head1 METHODS

=head2 psw_check ( [USER_ID], [PLAIN_PASSWD], [CRYPT_PASSWD] )

The password is collated.

=cut
sub psw_check {
	my($auth, $uid, $psw, $crypt)= @_;
	Digest::MD5::md5_hex($psw) eq $crypt ? 1: 0;
}

=head1 SEE ALSO

L<Egg::Plugin::SessionKit::Auth>,
L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
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

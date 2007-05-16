package Egg::Plugin::SessionKit::Auth::Crypt::Plain;
#
# Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>
#
# $Id: Plain.pm 151 2007-05-16 22:51:44Z lushe $
#
use strict;
use warnings;

our $VERSION= '2.01';

=head1 NAME

Egg::Plugin::SessionKit::Auth::Crypt::Plain - password in the plain text is collated.

=head1 SYNOPSIS

  use Egg qw/ SessionKit::Auth::File /;
    .......
    ...
    plugin_session=> {
      psw_crypt_type => 'Plain',
      .......
      ...
      },

=head1 DESCRIPTION

The password preserved without encrypting it is collated.

=head1 METHODS

=head2 psw_check ( [USER_ID], [PLAIN_PASSWD], [CRYPT_PASSWD] )

The password is collated.

=cut
sub psw_check {
	my($auth, $uid, $psw, $crypt)= @_;
	$psw eq $crypt ? 1: 0;
}

=head1 SEE ALSO

L<Egg::Plugin::SessionKit::Auth>,
L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
L<Egg::Plugin::SessionKit::Auth::Crypt::MD5>,
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

package Egg::Plugin::SessionKit::Auth::Crypt::Plain;
#
# Copyright (C) 2006 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>
#
# $Id: Plain.pm 70 2007-03-26 02:29:02Z lushe $
#
use strict;

our $VERSION= '0.01';

sub psw_check {
	my($auth, $uid, $psw, $crypt)= @_;
	$psw eq $crypt ? 1: 0;
}

1;

__END__

=head1 NAME

Egg::Plugin::SessionKit::Auth::Crypt::Plain - A plain text is used for the password check.

=head1 SYNOPSIS

Configuration.

  plugin_session=> {
    ...
    ...
    psw_crypt_type=> 'Plain',
    },

=over 4

=item psw_check,

These methods are called from the base module.

=back

=head1 SEE ALSO

L<Egg::SessionKit>,
L<Egg::SessionKit::Auth>,
L<Egg::Release>,

=head1 AUTHOR

Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>

=head1 COPYRIGHT

Copyright (C) 2007 by Bee Flag, Corp. E<lt>L<http://egg.bomcity.com/>E<gt>, All Rights Reserved.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

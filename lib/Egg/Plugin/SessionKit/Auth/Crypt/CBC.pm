package Egg::Plugin::SessionKit::Auth::Crypt::CBC;
#
# Copyright (C) 2006 Bee Flag, Corp, All Rights Reserved.
# Masatoshi Mizuno E<lt>mizunoE<64>bomcity.comE<gt>
#
# $Id: CBC.pm 70 2007-03-26 02:29:02Z lushe $
#
use strict;
use NEXT;
use Error;

our $VERSION= '0.02';

sub startup {
	my($class, $e, $aconf)= @_;
	$e->isa('Egg::Plugin::Crypt::CBC')
	  || throw Error::Simple q/Please build in Egg::Plugin::Crypt::CBC./;
	$class->NEXT::startup($e, $aconf);
}
sub psw_check {
	my($auth, $uid, $psw, $crypt)= @_;
	my $plain= $auth->e->cbc_decode($crypt) || return 0;
	$psw eq $plain ? 1: 0;
}

1;

__END__

=head1 NAME

Egg::Plugin::SessionKit::Auth::Crypt::CBC - The password is checked by using Egg::Plugin::Crypt::CBC.

=head1 SYNOPSIS

Configuration.

  plugin_crypt_cbc=> {
    ...
    ...
    },
  plugin_session=> {
    ...
    ...
    psw_crypt_type=> 'CBC',
    },

* Please see the document of Egg::Plugin::Crypt::CBC.

=over 4

=item startup, psw_check,

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

package Egg::Plugin::SessionKit::Auth::File;
#
# Masatoshi Mizuno E<lt>lusheE<64>cpan.orgE<gt>
#
# $Id: File.pm 151 2007-05-16 22:51:44Z lushe $
#
use strict;
use warnings;
use base qw/Egg::Plugin::SessionKit::Auth/;

our $VERSION = '2.01';

=head1 NAME

Egg::Plugin::SessionKit::Auth::File - It attests it by the text data.

=head1 SYNOPSIS

  use Egg qw/ SessionKit::Auth::File /;
  __PACKAGE__->egg_startup(
    .......
    ...
    plugin_session=> {
      data_path => '<$e.dir.etc>/members.txt',
      separator => "\s+",
      constant  => [qw/ uid psw active email nickname /],
      .......
      ...
      },

=head1 DESCRIPTION

The text file base is attested by L<Egg::Plugin::SessionKit::Auth>.

Please refer to the document of L<Egg::Plugin::SessionKit::Auth>.

=head1 CONFIGURATION

=head2 data_path

PATH of text file used as attestation data.

Please set default.

=head2 separator

Regular expression used for delimiter of data.

For instance, if they are the following data, '\:' is set.

  user1:pasword1:....
  user2:pasword2:....

It is '\s+\:\s+' if there is a possibility that the blank mixes with the 
delimitation.

  user1  :  pasword1  :  ....
  user2  :  pasword2  :  ....

Default is '\t'.

=head2 constant

List of name that allocates delimited data.

  constant => [qw/ member_code uid psw active age address ... /],

=cut
sub _setup {
	my($e)= @_;
	$e->{session_auth_handler} ||= __PACKAGE__.'::handler';
	$e->SUPER::_setup;
}

package Egg::Plugin::SessionKit::Auth::File::handler;
use strict;
use warnings;
use Carp qw/croak/;
use base qw/Egg::Plugin::SessionKit::Auth::handler/;

=head1 METHODS

=cut
sub _startup {
	my($class, $e, $conf)= @_;
	$class->_initialize($conf);
	$conf->{constant} || die q{ Please setup constant. };
	ref($conf->{constant}) eq 'ARRAY'
	   || die q{ Please set constant by the ARRAY reference. };
	$conf->{data_path}    || die qq{ Please setup data_path. };
	-f $conf->{data_path} || die qq{ File not found : $conf->{data_path} };
	$conf->{separator} ||= "\t";
	$class->SUPER::_startup($e, $conf);
}

=head2 restore ( [USER_ID] )

Data is returned by the HASH reference when found looking for USER_ID from the 
attestation data.  0 returns when not found.

=cut
sub restore {
	my $auth= shift;
	my $uid = shift || croak q{ I want 'uid' };
	my($uname, $const, $separ)=
	   @{$auth->config}{qw/uid_db_field constant separator/};
	open FH, $auth->config->{data_path} || die $!;  ## no critic
	while (<FH>) { chomp;
		my %user;
		@user{@$const}= split /$separ/;
		if ($user{$uname} && $user{$uname} eq $uid) {
			close FH;
			return \%user;
		}
	}
	close FH;
	0;
}

=head1 SEE ALSO

L<Egg::Plugin::SessionKit>,
L<Egg::Plugin::SessionKit::Auth>,
L<Egg::Plugin::SessionKit::Auth::Crypt::CBC>,
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

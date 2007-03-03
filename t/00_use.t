
use Test::More tests => 5;
BEGIN {
	use_ok('Egg::Plugin::SessionKit::Auth');
	use_ok('Egg::Plugin::SessionKit::Auth::DBI');
#	use_ok('Egg::Plugin::SessionKit::Auth::DBIC');
	use_ok('Egg::Plugin::SessionKit::Auth::File');
	use_ok('Egg::Plugin::SessionKit::Auth::Crypt::CBC');
	use_ok('Egg::Plugin::SessionKit::Auth::Crypt::Plain');
	};


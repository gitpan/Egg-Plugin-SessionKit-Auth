package Example::DBIC::MySchema;
use strict;
use warnings;
# use base 'DBIx::Class::Schema';

use base qw/Egg::Model::DBIC::Schema/;

__PACKAGE__->config(
  dsn      => 'dbi:Pg:dbname=mydb',
  user     => 'db_user',
  password => 'db_password',
  options  => { AutoCommit => 1 },
  );

__PACKAGE__->load_classes;

1;

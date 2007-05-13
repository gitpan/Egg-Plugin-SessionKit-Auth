package Example::DBIC::MySchema::Sessions;
use strict;
use warnings;
use base 'DBIx::Class';

__PACKAGE__->load_components("PK::Auto", "Core");
__PACKAGE__->table("sessions");
__PACKAGE__->add_columns(
  "id",
  {
    data_type => "character",
    default_value => undef,
    is_nullable => 0,
    size => 32,
  },
  "lastmod",
  {
    data_type => "timestamp without time zone",
    default_value => undef,
    is_nullable => 1,
    size => 8,
  },
  "a_session",
  {
    data_type => "text",
    default_value => undef,
    is_nullable => 1,
    size => undef,
  },
);
__PACKAGE__->set_primary_key("id");

1;

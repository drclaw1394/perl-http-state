use strict;
use warnings;

use Test::More;
use HTTP::State;
use HTTP::State::Cookie;

my $jar=HTTP::State->new();

# Store cookies 
#
my @cookies=(
  cookie_struct (name=>"value1", expires=>(time +10), partitioned=>1)
);

my $url='http://test.com.au/some/path';
my @partition_key=(
  undef,
  "http://test.com.au",
  "http://testa.com.au",
  "http://testb.com.au",
);

for(@partition_key){
  $jar->store_cookies( $url, $_, undef, @cookies);
}


say STDERR join "\n", $jar->dump_cookies;

ok 1;

done_testing;

use strict;
use warnings;

use HTTP::State::Cookie qw|:constants :encode :decode cookie_struct|;
use HTTP::State;

use Test::More;

#Attempt creating a cookie jar
#
#

my $jar=HTTP::State->new;

ok $jar, "created ok";


# Create a cookie 'sent from the server'
#

my $cookie=cookie_struct(
  some_name=>"some_value",
  COOKIE_HTTPONLY, 1,
  COOKIE_MAX_AGE, 10
);

ok $cookie, "created cookie";

my $request_url="http://site.com.au/path/goes/here.pdf";

my $string=encode_set_cookie($cookie);

ok $string=~/some_name=some_value/, "set cookie encode";

#Add cookie to jar
$jar->store_cookies($request_url, undef, $string);

$cookie=cookie_struct(
  some_other_name=>"some_value2",
  httponly=>1,
  "max-age"=>2
);

$jar->store_cookies($request_url, undef, $cookie);


$cookie=cookie_struct(
  temp=>"some_value2",
  COOKIE_HTTPONLY, 1,
);

$jar->store_cookies($request_url, undef, $cookie);

#should be 3 cookies in the jar now



$cookie->[COOKIE_VALUE]="NEW VALUE";

#$jar->store_cookies($request_url,$cookie);

my $header=$jar->retrieve_cookies($request_url);


done_testing;

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
$jar->set_cookies($request_url, $string);

$cookie=cookie_struct(
  some_other_name=>"some_value2",
  httponly=>1,
  "max-age"=>2
);

$jar->set_cookies($request_url, $cookie);


$cookie=cookie_struct(
  temp=>"some_value2",
  COOKIE_HTTPONLY, 1,
);

$jar->set_cookies($request_url, $cookie);

#should be 3 cookies in the jar now



$cookie->[COOKIE_VALUE]="NEW VALUE";

#$jar->set_cookies($request_url,$cookie);

my $header=$jar->encode_request_cookies($request_url);

$jar->spurt_set_cookies("test.cookie.jar");

my $jar2=HTTP::State->new;
$jar2->slurp_set_cookies("test.cookie.jar");

done_testing;

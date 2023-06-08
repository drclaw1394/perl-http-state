use strict;
use warnings;
use feature ":all";
use Data::Dumper;
use Log::ger;
#use Log::ger::Output "Screen";
use Log::OK {
  lvl=>"info"
};
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

#my $request_url="http://username:password\@site.com.au/path/goes/here.pdf";
my $request_url="http://site.com.au/path/goes/here.pdf";


my $string=encode_set_cookie($cookie);

ok $string=~/some_name=some_value/, "set cookie encode";

$jar->set_cookies($request_url, $string);

$cookie=cookie_struct(
  some_other_name=>"some_value2",
  httponly=>1,
  "max-age"=>2
  #COOKIE_HTTPONLY, 1,
  #COOKIE_MAX_AGE, 2
);

$jar->set_cookies($request_url, $cookie);


$cookie=cookie_struct(
  temp=>"some_value2",
  COOKIE_HTTPONLY, 1,
);
$jar->set_cookies($request_url, $cookie);





$cookie->[COOKIE_VALUE]="NEW ZVALUE";

#$jar->set_cookies($request_url,$cookie);

my $header=$jar->encode_cookies($request_url);


$jar->spurt_set_cookies("test.cookie.jar");

my $jar2=HTTP::State->new;

$jar2->slurp_set_cookies("test.cookie.jar");



done_testing;

exit;

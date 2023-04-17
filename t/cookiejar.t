use strict;
use warnings;
use feature ":all";
use Data::Dumper;
use Log::ger;
use Log::ger::Output "Screen";
use Log::OK {
  lvl=>"info"
};
use HTTP::State qw|:constants|;

use Test::More;

#Attempt creating a cookie jar
#
#

my $jar=HTTP::State->new;

ok $jar, "created ok";


# Create a cookie 'sent from the server'
#

my $cookie=$jar->cookie_struct(
  some_name=>"some_value",
  COOKIE_HTTPONLY, 1,
  COOKIE_MAX_AGE, 10
);

ok $cookie, "created cookie";

#my $request_url="http://username:password\@site.com.au/path/goes/here.pdf";
my $request_url="http://site.com.au/path/goes/here.pdf";


my $string=$jar->encode_set_cookie($cookie);

ok $string=~/some_name=some_value/, "set cookie encode";

say STDERR $string;
$jar->set_cookies($request_url, $string);

$cookie=$jar->cookie_struct(
  some_other_name=>"some_value2",
  httponly=>1,
  "max-age"=>2
  #COOKIE_HTTPONLY, 1,
  #COOKIE_MAX_AGE, 2
);

say STDERR "++++++++";
$jar->set_cookies($request_url, $cookie);
say STDERR "++++++++";


$cookie=$jar->cookie_struct(
  temp=>"some_value2",
  COOKIE_HTTPONLY, 1,
);
$jar->set_cookies($request_url, $cookie);

say STDERR "DUMPING COOKIES";
say STDERR $jar->dump_cookies;




say STDERR "++++++++";
$cookie->[COOKIE_VALUE]="NEW ZVALUE";

#$jar->set_cookies($request_url,$cookie);
say STDERR "++++++++";

my $header=$jar->encode_cookies($request_url);
say STDERR Dumper $header;
say STDERR Dumper $jar->get_kv_cookies($request_url);

say STDERR "DUMPING COOKIES";
say STDERR $jar->dump_cookies;

$jar->spurt_set_cookies("test.cookie.jar");

say STDERR "Slurped";
my $jar2=HTTP::State->new;

$jar2->slurp_set_cookies("test.cookie.jar");
say STDERR $jar2->dump_cookies;



done_testing;

exit;

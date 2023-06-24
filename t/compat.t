use strict;
use warnings;
use feature ":all";
use Log::ger::Output "Screen";
use Log::OK {
    opt=>"verbose",
    lvl=>"info"
  };

use Data::Dumper;

use Test::More;
use HTTP::State ":flags";
use HTTP::State::Cookie ":all";

use HTTP::CookieJar;
#say Dumper my $test=cookie_struct(name=>"value", "Expires"=>(time));
#say Dumper encode_set_cookie $test;


say time;

my @strings=(
  #encode_set_cookie cookie_struct(name=>"value", "Max-Age"=>1),
  encode_set_cookie cookie_struct(name=>"value", "Expires"=>(time+1))
);

my $state_jar=HTTP::State->new();
my $cookie_jar=HTTP::CookieJar->new();

my $url='http://my.site.com.au/path/to/file.pdf';
for (@strings){
  say "ADDiNG STRING: $_";
  $state_jar->add($url, $_);
  $cookie_jar->add($url, $_);
}

use Data::Dumper;
say STDERR "HTTP::State";
say STDERR Dumper $state_jar->dump_cookies;#({persistent=>0});

say STDERR "HTTP::CookieJar";
say STDERR Dumper $cookie_jar->dump_cookies;#({persistent=>0});

ok 1;
say STDERR "";
done_testing;

use strict;
use feature ":all";
use Log::ger::Output "Screen";
use Log::OK {
  lvl=>"trace"
};
use Test::More;
use HTTP::State ":constants";

my $jar=HTTP::State->new;

my $domain;
my $path;
my $name="test";
my $value;

my $url;
my $cookie=$jar->cookie_struct(
  $name=>$value,
  domain=>$domain,
  path=>$path
);


{
  
  # DEFAULT DOMAIN
  #
  my $url="http://test.example.com.au";
  $jar->clear;
  $jar->set_cookies($url, $cookie);
  my $encoded=$jar->dump_cookies;
  
  # no domain set use the url as default
  ok $encoded=~/Domain=test\.example\.com\.au/, "Default domain";
  ok $encoded=~/Path=\//, "Default path";
}

{
  # DEFAULT PATH
  #
  $jar->clear;
  $cookie=$jar->cookie_struct(
    $name=>$value,
    domain=>$domain,
    path=>$path
  );
  my $url="http://test.example.com.au/my/path/here/da.pdf";
  $jar->set_cookies($url,$cookie);

  my $encoded=$jar->dump_cookies;
  say STDERR $encoded;
  ok  $encoded=~/Path=\/my\/path\/here/, "Default Path. Upto right most /";
}
{
  # Prevent domain attribute targeting sub domains.
  #
  $jar->clear;
  $cookie=$jar->cookie_struct(
    $name=>$value,
    domain=>"a.test.example.com.au",
    path=>$path
  );
  
  $url="http://test.example.com.au/my/path/here/da.pdf";
  $jar->set_cookies($url,$cookie);

  my $encoded=$jar->dump_cookies;
  say STDERR $encoded;
  ok $encoded eq "", "Attempt sub domain cookie set";
}
{
  # Prevent domain attribute targeting public suffix domain
  #
  $jar->clear;
  $cookie=$jar->cookie_struct(
    $name=>$value,
    domain=>"com.au",
    path=>$path
  );
  
  $url="http://test.example.com.au/my/path/here/da.pdf";
  $jar->set_cookies($url,$cookie);

  my $encoded=$jar->dump_cookies;
  say STDERR $encoded;
  ok $encoded eq "", "Ignore Attempt public domain cookie set";
}

{
  # Test cookies with different domains and same path and name 
  # adding correctly
  #
  $jar->clear;
  for(qw<a b c d e>){
    $url="http://dd.$_.example.com/";
    $cookie=$jar->cookie_struct(
      name=>"my_cookie",
      domain=>"dd.$_.example.com",
    );
    $jar->set_cookies($url, $cookie);
  }
    $url="http://dd.dd.example.com/";
    $cookie=$jar->cookie_struct(
      name=>"my_cookie",
      domain=>"dd.dd.example.com",
    );
    $jar->set_cookies($url, $cookie);
  my $encoded=$jar->dump_cookies;

  ok split("\n", $encoded)==6, "Count ok";
}

{
  # Set a cookie with the same name and path but different domains
  #
  $jar->clear;
  $url="http://dd.dd.example.com/";
  $cookie=$jar->cookie_struct(
    name=>"my_cookie",
    domain=>"dd.dd.example.com",
  );

  $jar->set_cookies($url, $cookie) for 1..5;
  my $encoded=$jar->dump_cookies;

  ok split("\n", $encoded)==1, "Count ok";

}

{
  # Invariant creation time for cookie replacement
  #
  $jar->clear;
  $url="http://dd.dd.example.com/";
  $cookie=$jar->cookie_struct(
    name=>"my_cookie",
    domain=>"dd.dd.example.com",
  );

  $jar->set_cookies($url, $cookie);
  my $db=$jar->db;
  my $time=$db->[0][COOKIE_CREATION_TIME];
  say STDERR $time;
  sleep 1;
  
  $jar->set_cookies($url, $cookie);
  say STDERR join ", ", @$db;
  ok @$db==1, "Count ok";

  my $new_time=$db->[0][COOKIE_CREATION_TIME];
  ok $new_time == $time, "Creation time ok";
}

done_testing;

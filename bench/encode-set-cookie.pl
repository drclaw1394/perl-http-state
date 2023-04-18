use v5.36;
use Log::ger::Output "Screen";
use Log::OK {
    lvl=>"info",
  };
use HTTP::State;
#use Cookie;
use HTTP::CookieJar;
use Benchmark qw<cmpthese timethese>;
use Data::Dumper;

my $count=1000;#$ARGV[0]//1;
my $name="name";
my $value="some string goes here";


# Generate random domains
my @domains;
my @paths;
{
  my $levels=2;
  my $tld="com.au";

  for(1..$count){
    my $d="";
    for(1..1+int(rand($levels))){
      my $label=join "", map {chr(ord("a")+rand(26))} 1..5;
      $d.=$label.".";
    }
    $d.=$tld;
    push @domains, $d;
  }
  #say join "\n", @domains;
}
{
  my $levels=4;
  #make paths
  #
  for(0..$#domains){
    my $d="/";
    for(1..1+int(rand($levels))){
      my $label=join "", map {chr(ord("a")+rand(26))} 1..5;
      $d.=$label."/";
    }
    push @paths, $d;
  }
  #say join "\n", @paths;
}
my @cookies;
{
  #Make cookies
  for(0..$#domains){
    my $key=join "", map {chr(ord("a")+rand(26))} 1..5;
    my $value=join "", map {chr(ord("a")+rand(26))} 1..10;
    my $path=$paths[$_];
    my $domain=$domains[$_];
    push @cookies, "$key=$value; path=$path; domain=$domain;"; 
  }
}
#say join "\n", @cookies;

#Data set is created now sample a by created random  urls from data 


my @urls;
for(1..1000){
  my $i=rand @domains;
  my $host=$domains[$i];
  my $path=$paths[$i];
  push @urls, "http://$host$path";
}

say "Query set is: ", join "\n", @urls;

my $http_state_jar=HTTP::State->new;
my $http_cookiejar=HTTP::CookieJar->new;



my @sample=map {$cookies[rand @cookies]} 1..@urls;

say join "\n", @sample;
cmpthese 100, {
  http_state=>sub { 
    for(0..$#urls){
      $http_state_jar->set_cookies($urls[$_], $sample[$_]);
    }
  },
  http_cookiejar=>sub {
    for(0..$#urls){
      $http_cookiejar->add($urls[$_], $sample[$_]);
    }
  }

};


my @results=([],[]);
cmpthese 100, {
  http_state=>sub { 
    for(@urls){
      say $_;
      my $string=$http_state_jar->encode_cookies($_);
      #say "http_state: ".$string if $string;
      push $results[0]->@*, $string;
    }
  },
  http_cookiejar=>sub {
    for(@urls){
      my $string=$http_cookiejar->cookie_header($_);
      #say "http_cookiejar: ".$string if $string;
      push $results[1]->@*, $string;
    }
  }

};

my $ok=1;

for(0..$results[0]->@*-1){
  my $ok=($results[0][$_] eq $results[1][$_]);

  #Print infor on mis matched items
  say "$results[0][$_], $results[1][$_]" if $results[1][$_];
  unless($ok){
    say "miss match for $urls[$_]";
  }

}
#say "results ok: $ok";


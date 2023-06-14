use v5.36;
use Log::ger::Output "Screen";
use Log::OK {
    lvl=>"info",
  };
use HTTP::State::Cookie qw<:encode :decode>;
use HTTP::State;
#use Cookie;
use HTTP::CookieJar;
use Protocol::HTTP::CookieJar;

use Benchmark qw<cmpthese timethese>;
use Data::Dumper;

my $origin_count=1000;#$ARGV[0]//1;
my $path_count=1000;
my $cookie_count=1000;
my $name="name";
my $value="some string goes here";


# Generate random domains
my @domains;
my @paths;
my @cookies;
my @proto_cookies;
my @urls;

{
  my $levels=2;
  my $tld="com.au";

  for(1..$origin_count){
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
  for(1..$path_count){
    my $d="/";
    for(1..1+int(rand($levels))){
      my $label=join "", map {chr(ord("a")+rand(26))} 1..5;
      $d.=$label."/";
    }
    push @paths, $d;
  }
  #say join "\n", @paths;
}

{
  #Make cookies
  for(1..$cookie_count){
    my $key=join "", map {chr(ord("a")+rand(26))} 1..5;
    my $value=join "", map {chr(ord("a")+rand(26))} 1..10;
    my $path=$paths[rand @paths];
    my $domain=$domains[rand @domains];
    push @cookies, "$key=$value; path=$path; domain=$domain; Secure"; 
    push @proto_cookies, [name=>$key,path=>$path, domain=>$domain];
    my $url= "https://$domain$path"."a";
    push @urls,$url;
  }
}
#say join "\n", @cookies;

#Data set is created now sample a by created random  urls from data 



#say "Query set is: ", join "\n", @urls;

my $http_state_jar=HTTP::State->new(suffix_cache=>{});
my $http_cookiejar=HTTP::CookieJar->new;
my $protocol_http_jar=Protocol::HTTP::CookieJar->new;



my @sample=map int rand(@cookies), 1..50;
#say join "\n", map $urls[$_], @sample;

cmpthese 1000, {
  http_state=>sub { 
    for(@sample){
      #say $urls[$_];
      #say $cookies[$_];
      $http_state_jar->set_cookies($urls[$_], $cookies[$_]);
    }
  },
  http_cookiejar=>sub {
    for(@sample){
      $http_cookiejar->add($urls[$_], $cookies[$_]);
    }
  },

  protocol_http=>sub {

    for(@sample){
      my $copy=decode_set_cookie($cookies[$_]);
      my $hash=hash_set_cookie($copy);

      $protocol_http_jar->add(delete($hash->{name}), $hash, URI::XS->new($urls[$_]));
    }
  }


};

#Confirm sizes of cookie jars
say "Size of http_state: ".$http_state_jar->db->@*;
say "Size of http_cookiejar: ".$http_cookiejar->_all_cookies;
say "Size of protocol http_cookiejar: ".keys $protocol_http_jar->all_cookies->%*;
#exit;

my @samples=map int rand(@urls), 1..15;
my @results=([],[],[]);
cmpthese 1000, {
  http_state=>sub { 
    for(@samples){
      #say $_;
      my $string=$http_state_jar->encode_request_cookies($urls[$_]);
      #say "http_state: ".$string if $string;
      push $results[0]->@*, $string;
    }
  },
  #############################################################
  # http_cookiejar=>sub {                                     #
  #   for(@samples){                                          #
  #     my $string=$http_cookiejar->cookie_header($urls[$_]); #
  #     #say "http_cookiejar: ".$string if $string;           #
  #     push $results[1]->@*, $string;                        #
  #   }                                                       #
  # },                                                        #
  #############################################################

  #####################################################################################
  # protocol_http=>sub {                                                              #
  #   for(@samples){                                                                  #
  #     my $array=$protocol_http_jar->find(URI::XS->new($urls[$_]));                  #
  #     #say "size : ". scalar @$array;                                               #
  #     #say "http_cookiejar: ".$string if $string;                                   #
  #     if(keys $array->[0]->%*){                                                     #
  #       #say "domain :$_->{domain} path : $_->{path} name: $_->{name}" for @$array; #
  #       my $string= join "; ", map "$_->{name}=$_->{value}", $array->[0];           #
  #       #say "protocol_http: ".$string;                                             #
  #       push $results[2]->@*, $string;                                              #
  #     }                                                                             #
  #     else{                                                                         #
  #       push $results[2]->@*, "";                                                   #
  #     }                                                                             #
  #   }                                                                               #
  # }                                                                                 #
  #####################################################################################

};
my $ok=1;
exit;
say "Found ".$results[0]->@*." cookies";
for(0..$results[0]->@*-1){
  my $ok=($results[0][$_] eq $results[1][$_]);
   $ok&&=($results[1][$_] eq $results[2][$_]);

  #Print infor on mis matched items
  unless($ok){
    #say "miss match for $urls[$_]";
    say "$results[0][$_]| $results[1][$_]| $results[2][$_]" if $results[1][$_];
  }

}
#say "results ok: $ok";


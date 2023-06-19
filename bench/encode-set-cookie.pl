use v5.36;
use Log::ger::Output "Screen";
use Log::OK {
    lvl=>"info",
    opt=>"verbose"
  };
use HTTP::State::Cookie qw<:encode :decode>;
use HTTP::State ":constants";
#use Cookie;
use HTTP::CookieJar;
use Protocol::HTTP::CookieJar;

use Benchmark qw<cmpthese timethese>;
use Data::Dumper;
my $count=200;
my $origin_count=$count;#1000;#$ARGV[0]//1;
my $path_count=$count;#1000;
my $cookie_count=$count;#1000;
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
    push @cookies, my $c="$key=$value; Path=$path; Domain=$domain; Secure; Max-Age=10"; 
    #say $c;
    push @proto_cookies, [name=>$key,path=>$path, domain=>$domain];
    my $url= "https://$domain$path";
    push @urls,$url;
  }
}
#say join "\n", @cookies;

#Data set is created now sample a by created random  urls from data 



#say "Query set is: ", join "\n", @urls;

my $http_state_jar=HTTP::State->new;#(suffix_cache=>{});
my $http_cookiejar=HTTP::CookieJar->new;
my $protocol_http_jar=Protocol::HTTP::CookieJar->new;



my @sample=map int rand(@cookies), 1..@cookies;
#say join "\n", map $urls[$_], @sample;

cmpthese 1, {
  http_state=>sub { 
    for(@sample){
      #say $urls[$_];
      #say $cookies[$_];
      $http_state_jar->set_cookies($urls[$_], 0xFF, $cookies[$_]);
      #say Dumper $http_state_jar->db;
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
      #say join ", ",%$hash;
      $protocol_http_jar->add(delete($hash->{name}), $hash, URI::XS->new($urls[$_]), Date::now());
    }
  }


};


#Confirm sizes of cookie jars
say "Size of http_state: ".$http_state_jar->db->@*;
#map {say encode_set_cookie $_} $http_state_jar->db->@*;
#say Dumper $http_state_jar->db;
say "";
say "Size of http_cookiejar: ".$http_cookiejar->_all_cookies;
#map {my @keys=sort keys %$_; my $h=$_; say join "; ", map  {($_, $h->{$_})} @keys} $http_cookiejar->_all_cookies;
say "";
my $all=$protocol_http_jar->all_cookies;
my @flat;
for my ($domain, $list)(%$all){
  for my $c (@$list){
    my $string= join "; ", map "$_->{name}=$_->{value}", $c;
    #say $string;
    push @flat, $string;
  }
}
say "Size of protocol http_cookiejar: ".@flat;
#map {my @keys=sort keys %$_; my $h=$_; say join "; ", map  {my $domain=$_; $h->{$_}->@*} @keys} $protocol_http_jar->all_cookies;

my @samples=map int rand(@urls), 1..@cookies;
my @results=([],[],[]);
cmpthese -1, {
  http_state=>sub { 
    for(@samples){
      #say $urls[$_];
      my $string=$http_state_jar->encode_request_cookies($urls[$_]);
      #say "http_state: ".$string if $string;
      push $results[0]->@*, $string;
    }
  },
  http_cookiejar=>sub {
    for(@samples){
      my $string=$http_cookiejar->cookie_header($urls[$_]);
      #say "http_cookiejar: ".$string if $string;
      push $results[1]->@*, $string;
    }
  },

  protocol_http=>sub {
    for(@samples){
      my $array=$protocol_http_jar->find(my $url=URI::XS->new($urls[$_]), URI::XS->new($urls[$_]), Date::now(), Date::now());
      #say $url;
      #say "size : ". scalar @$array;
      #say "http_cookiejar: ".$string if $string;
      #say $urls[$_];
      #say Dumper $array;
      for my $c (@$array){
        if(keys $c->%*){
          #say "domain :$_->{domain} path : $_->{path} name: $_->{name}" for @$array;
          my $string= join "; ", map "$_->{name}=$_->{value}", $c;
          #say "protocol_http: ".$string;
          push $results[2]->@*, $string;
        }
        else{
          push $results[2]->@*, "";
        }
      }
    }
  }

};

exit;
my $ok=1;

say "Found ".$results[0]->@*." cookies";
for(0..$results[0]->@*-1){
  my $ok=($results[0][$_] eq $results[1][$_]);
  #$ok&&=($results[1][$_] eq $results[2][$_]);

  #Print infor on mis matched items
  unless($ok){
    #say "miss match for $urls[$_]";
    say "$results[0][$_]| $results[1][$_]| $results[2][$_]" if $results[1][$_];
  }

}
#say "results ok: $ok";


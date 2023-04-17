use v5.36;
use Log::ger::Output "Screen";
use Log::OK {
    lvl=>"info",
  };
use HTTP::State;
#use Cookie;
use HTTP::CookieJar;
use Benchmark qw<cmpthese>;
use Data::Dumper;

my $count=10000;#$ARGV[0]//1;
my $name="name";
my $value="some string goes here";


my $http_state_jar=HTTP::State->new;
my $http_cookiejar=HTTP::CookieJar->new;

sub http_state{
 
  my $cookie=$http_state_jar->cookie_struct($name=>$value);
  my $string=$http_state_jar->encode_set_cookie($cookie);

}

##########################################################
# sub cookie_jar {                                       #
#                                                        #
#   my $c = Cookie->new( name => $name, value=> $value); #
#   my $string=$c->as_string;                            #
#   say $string;                                         #
# }                                                      #
##########################################################


#################################
# cmpthese($count, {            #
#                               #
#     http_state=>\&http_state, #
#     #cookie_jar=>\&cookie_jar #
#   });                         #
#################################


# set cookie via string

my $url="http://example.com.au/some/path/file.txt";
sub http_state_add($id){
  my $string="$name$id=$value; HTTPOnly=1; Secure=1;";

  $http_state_jar->set_cookies($url=~s/example/example$id/r, $string);
  #say "http_state:".$http_state_jar->dump_cookies;
}

sub http_cookiejar_add($id){
  my $string="$name$id=$value HTTPOnly=1; Secure=1;";
  $http_cookiejar->add($url=~s/example/example$id/r,$string);
  #say "http_cookiejar: ", $http_cookiejar->dump_cookies;
}

say "COUNT $count";
cmpthese $count, {
  http_state=>sub {state $i=0;http_state_add($i++)},
  http_cookiejar=>sub {state $i=0; http_cookiejar_add($i++)}
};


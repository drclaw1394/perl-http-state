use v5.36;
use HTTP::State::Cookie qw":all";
use Mojo::Cookie::Request;

use CGI ":standard";
use CGI::Cookie;
use Dancer::Cookie;
#use Cookie;

use Benchmark qw<cmpthese>;
# Create a cookie
#
my $count=$ARGV[0]//-1;
cmpthese $count ,
{
  hsc=>sub {
    cookie_struct name=>"value";
  },

  mcr=>sub {
    Mojo::Cookie::Request->new({name=>"name", value=>"value"});
  },

  ##############################################
  # c=>sub {                                   #
  #   Cookie->new(name=>"name",value=>"value") #
  # },                                         #
  ##############################################
  cc=>sub{
    CGI::Cookie->new(-name=>'ID',-value=>123456);
  },

  dc=>sub {
    Dancer::Cookie->new( name => "name", value => "value");
  }
};

my %cookies=(

    hsc=>cookie_struct(name=>"value"),
    mcr=>Mojo::Cookie::Request->new({name=>"name", value=>"value"}),
    cc=>CGI::Cookie->new(-name=>'name',-value=>"value"),
    dc=>Dancer::Cookie->new( name => "name", value => "value")
  );

# Encode a simple kv cookie (request

  use Data::Dumper;
  say Dumper \%cookies;
cmpthese $count,{

  hsc=>sub {
    encode_cookies $cookies{hsc}
  },
  mcr=>sub {
    $cookies{mcr}->to_string()
  },
  cc=>sub{
    # NOTE this renders multiple header lines, nothing to to with cookies
    header(-cookie=>$cookies{cc});
  }
};




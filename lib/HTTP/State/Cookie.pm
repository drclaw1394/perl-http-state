use strict;
use warnings;
package HTTP::State::Cookie;
# Logging
#
use Log::ger; 
use Log::OK;


use Exporter "import";

use feature qw"say signatures";
use Data::Dumper;
use builtin qw<trim>;


my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my $i=0;
my %months= map {$_,$i++} @months;

$i=0;
my @days= qw(Sun Mon Tue Wed Thu Fri Sat);
my %days= map {$_,$i++} @days;

my @names;
my @values;
my %const_names;

BEGIN {
	@names=qw<
		Undef
		Name
		Value
		Expires
		Max-Age
		Domain
		Path
		Secure
		HTTPOnly
		SameSite
    
    Creation-Time
    Last-Access-Time
    Persistent
    Host-Only
    Key

	>;
	@values= 0 .. @names-1;

	my @same_site=qw<Lax Strict None>;

	my @pairs=
		(map { (("COOKIE_".uc $names[$_])=~tr/-'/_/r, $values[$_]) } 0..@names-1),	#elements
		(map {("SAME_SITE_".uc, $_)} @same_site)						#same site vals
	;						

	%const_names=@pairs;
}

use constant \%const_names;

my %reverse; @reverse{map lc, @names}=@values;
$reverse{undef}=0;			#catching

our @EXPORT_OK=(
  keys(%const_names),
  "encode_cookies",
  "encode_set_cookie",      #encodes a standalone cookie struct
  "decode_set_cookie",      #decodes a string into a cookie struct
  "decode_cookies",          #decodes a strin of kv cookie pairs into an array
                            # NOTE encoding a cookie is via a cookie jar object
  "cookie_struct",
  "hash_set_cookie"
);

our %EXPORT_TAGS=(
  "constants"=>["cookie_struct", keys %const_names],      
  "encode"=>["cookie_struct", "encode_set_cookie", "encode_cookies", "hash_set_cookie"],
  "decode"=>["cookie_struct", "decode_set_cookie", "decode_cookies"],
  "all"=>[@EXPORT_OK]
);

our @EXPORT=("cookie_struct");



use Time::Piece;
use Time::Local qw<timegm_modern>;

my $tz_offset=Time::Piece->localtime->tzoffset;


# Expects the name and value as the first pair of arguments
sub cookie_struct {

  no warnings "experimental";
  my @c=(1, shift, shift);  # Reuse the first field as string/int marker

  #$c[COOKIE_NAME]=shift;
  #$c[COOKIE_VALUE]=shift;

  die "Cookie must have a name" unless $c[COOKIE_NAME];

  if(@_){
    no warnings "uninitialized";
    no warnings "numeric";
    if($c[$_[0]]){
      # anticipate keys provided as string.
      #
      # If the first remaining argument is numeric (field constant) will be an undef value
      # which when used in numeric constant will be 0. The $c[0] is set to one which is true
      # which means we anticipate string names
      for my ($k, $v)(@_){
        $c[$reverse{lc $k}]=$v;
      }
    }
    else{
      # keys assumed to be integer constants
      # 
      for my ($k, $v)(@_){
        $c[$k]=$v;
      }
    }

    $c[COOKIE_EXPIRES]-=$tz_offset if defined $c[COOKIE_EXPIRES];
    $c[COOKIE_DOMAIN]=scalar reverse $c[COOKIE_DOMAIN] if $c[COOKIE_DOMAIN];
  }

  # Remove any extra fields added in haste
  #
  #splice @c, COOKIE_KEY+1;

  \@c;
}


# Supports a simple scalar or an array ref of simple scalars to parse/decode
sub decode_cookies {
  no warnings "experimental";
  my @values= map trim($_),            #trim leading /trailing white space 
              map split("=", $_, 2),  #Split files into  KV pairs
              split /;\s*/, ref($_[0])
                ?join("; ", $_[0]->@*)
                : $_[0];    #Split input into fields
	@values;
}

# Returns a newly created cookie struct from a Set-Cookie string. Does not
# validate or create default values of attributess. Only processes what is
# given
# Parsing is done according with RFC6265bis no RFC6265
#
sub decode_set_cookie{
  no warnings "experimental";
  # $string, converter
  my $input=$_[0];
	my $key;
	my $value;
	my @values;
	my $first=1;
  my @fields;#=split /;\s*/, $_[0];

  #Value needs to be the first field 

  my $index=index $input, ";";
  my $name_value;
  if($index>=0){
    # at least one ";"  was found
    $name_value=substr $input,0, $index;
    substr $input, 0, $index+1, "";
    
  }
  else {
    # No ";" found
    $name_value=$input;
    $input="";
  }
 
  Log::OK::TRACE and log_trace " decoding cookie name: name value: $name_value";

  $index=index $name_value, "=";

  #Abort unless has a name
  return unless $index >0;

  $values[1]= substr $name_value, 0, $index;
  $values[2]= substr $name_value, $index+1;
  Log::OK::TRACE and log_trace " decoding cookie name: $values[1] value:$values[2]";


  # trip whitespace
  $values[1]=trim($values[1]);
  $values[2]=trim($values[2]);

  # TODO: test for controll characters
  


  Log::OK::TRACE and log_trace " decoding cookie name: $values[1] value:$values[2]";

  #Process attributes if input remaining;
  return \@values unless $input;

  @fields=split /;\s*/, $input;

	for(@fields){

		($key, $value)=split "=", $_, 2;

    $key=trim($key);
    $value=trim($value) if $value;

    # Attributes are processed with case insensitive names
    #
    $key=lc $key;

    # Look up the value key value pair
    # unkown values are stored in the undef => 0 position
    $values[$reverse{$key}]=$value//1;
	}

  # nuke unkown value
  $values[0]=undef;


  # Fix the date. Date is stored in seconds internally
  #
  for($values[COOKIE_EXPIRES]//()){
    my ($wday_key, $mday, $mon_key, $year, $hour, $min, $sec, $tz)=
     /([^,]+), (\d+).([^-]{3}).(\d{4}) (\d+):(\d+):(\d+) (\w+)/;
     #TODO support parsing of other deprecated data formats

    if(70<=$year<=99){
      $year+=1900;
    }
    elsif(0<=$year<=69){
      $year+=2000;
    }
    else{
      #year as is
    }
    $_ = timegm_modern($sec, $min, $hour, $mday, $months{$mon_key}, $year);
  }


  for($values[COOKIE_DOMAIN]//()){
    s/\.$//;
    s/^\.//;
    $_ = scalar reverse $_;
  }

  \@values;
}

# Encodes KV pairs from supplied cookie structs
sub encode_cookies {
  join "; ", map "$_->[COOKIE_NAME]=".($_->[COOKIE_VALUE]//""), @_;
}

sub encode_set_cookie ($cookie, $store_flag=undef){
	Log::OK::DEBUG and log_debug "Serializing set cookie";	

  # Start with name and value
  #
	my $string= "$cookie->[COOKIE_NAME]=".($cookie->[COOKIE_VALUE]//"");			

  # Reverse the cookie domain (stored backwards) if preset. Don't add the attribute
  # if not defined.
  #
  $string.= "; $names[COOKIE_DOMAIN]=".scalar reverse $_ 
    for $cookie->[COOKIE_DOMAIN]//();

  # Do Attributes with needing values.  Only add them if the attribute is
  # defined
  #
	for my $index (COOKIE_MAX_AGE, COOKIE_PATH, COOKIE_SAMESITE){	
		for($cookie->[$index]//()){
			$string.="; $names[$index]=$_";
		}
	}

	
  # Format date for expires. Internally the cookie structure stores this value
  # in terms of GMT.
  # Again only add the attribute if value is defined
  #
	for($cookie->[COOKIE_PERSISTENT] && $cookie->[COOKIE_EXPIRES]//()){
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =gmtime $_;
    $string.="; $names[COOKIE_EXPIRES]=$days[$wday], $mday-$months[$mon]-".($year+1900) ." $hour:$min:$sec GMT";
	}

  # Do flags (attibutes with no values)
  #
	$string.="; $names[COOKIE_SECURE]" if defined $cookie->[COOKIE_SECURE];				
	$string.="; $names[COOKIE_HTTPONLY]" if defined $cookie->[COOKIE_HTTPONLY];

  if($store_flag){
    # If asked for storage format, give internal values
    #
	  $string.="; Host-Only" if defined $cookie->[COOKIE_HOST_ONLY];				
	  $string.="; Creation-Time=$cookie->[COOKIE_CREATION_TIME]";
	  $string.="; Last-Access-Time=$cookie->[COOKIE_LAST_ACCESS_TIME]";
	  $string.="; Persistent" if $cookie->[COOKIE_PERSISTENT];
  }

	$string;

}

sub hash_set_cookie($cookie, $store_flag=undef){
	my %hash=(name=>$cookie->[COOKIE_NAME], value=>$cookie->[COOKIE_VALUE]);

  # Reverse the cookie domain (stored backwards) if preset. Don't add the attribute
  # if not defined.
  #
  $hash{$names[COOKIE_DOMAIN]}=scalar reverse $_ 
    for $cookie->[COOKIE_DOMAIN]//();

  # Do Attributes with needing values.  Only add them if the attribute is
  # defined
  #
	for my $index (COOKIE_MAX_AGE, COOKIE_PATH, COOKIE_SAMESITE){	
		for($cookie->[$index]//()){
			$hash{$names[$index]}=$_;
		}
	}

	
  # Format date for expires. Internally the cookie structure stores this value
  # in terms of GMT.
  # Again only add the attribute if value is defined
  #
	for($cookie->[COOKIE_PERSISTENT] && $cookie->[COOKIE_EXPIRES]//()){
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =gmtime $_;
    $hash{Expires}="$days[$wday], $mday-$months[$mon]-".($year+1900) ." $hour:$min:$sec GMT";
	}

  # Do flags (attibutes with no values)
  #
	$hash{Secure}=1 if defined $cookie->[COOKIE_SECURE];				
	$hash{HTTPOnly}=1 if defined $cookie->[COOKIE_HTTPONLY];

  if($store_flag){
    # If asked for storage format, give internal values
    #
	  $hash{"Host-Only"}=1 if defined $cookie->[COOKIE_HOST_ONLY];				
	  $hash{"Creation-Time"}=$cookie->[COOKIE_CREATION_TIME];
	  $hash{"Last-Access-Time"}=$cookie->[COOKIE_LAST_ACCESS_TIME];
  }

	\%hash;
}

1;

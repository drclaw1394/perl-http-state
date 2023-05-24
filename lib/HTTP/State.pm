package HTTP::State;
# Please refer to:
# https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes

use feature "say";

our $VERSION="v0.1.0";

# Logging
#
use Log::ger; 
use Log::OK;

use builtin qw<trim>;

# Debug
#
#use Data::Dumper;

my @names;
my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
my $i=0;
my %months= map {$_,$i++} @months;

my $i=0;
my @days= qw(Sun Mon Tue Wed Thu Fri Sat);
my %days= map {$_,$i++} @days;
my %const_names;

my @values;

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

# Object system. Will use feature class asap
#
use Object::Pad;



# Fast Binary Search subroutines
#
use List::Insertion {type=>"string", duplicate=>"left", accessor=>"->[".COOKIE_KEY."]"};


# Public suffix list list
#
#use Mozilla::PublicSuffix qw<public_suffix>;

# Date 
use Time::Piece;
use Time::Local qw<timegm_modern>;

# Exports
use Exporter qw(import);


our @EXPORT_OK=(
  keys(%const_names),
  "encode_set_cookie",      #encodes a standalone cookie struct
  "decode_set_cookie",      #decodes a string into a cookie struct
  "decode_cookies",          #decodes a strin of kv cookie pairs into an array
                            # NOTE encoding a cookie is via a cookie jar object
  "cookie_struct",
  "hash_set_cookie"
);

our %EXPORT_TAGS=(
  "constants"=>[keys %const_names],      
  "encode"=>["encode_set_cookie", "hash_set_cookie"],
  "decode"=>["decode_set_cookie", "decode_cookies"],
  "all"=>[@EXPORT_OK]
);

my $tz_offset=Time::Piece->localtime->tzoffset;

sub cookie_struct {

  no warnings "experimental";
  my @c;
  
  $c[0]=1;

	$c[COOKIE_NAME]=shift;
	$c[COOKIE_VALUE]=shift;

  die "Cookie must have a name" unless $c[COOKIE_NAME];

  no warnings "uninitialized";
  no warnings "numeric";

  if($c[$_[0]]){
    # anticipate keys provided as string.
    for my ($k, $v)(@_){

      $c[$reverse{lc $k}]=$v;
    }

  }
  else{
    # keys assumed to be integer constants
    for my ($k, $v)(@_){
      $c[$k]=$v;
    }
  }

  $c[COOKIE_EXPIRES]-=$tz_offset if defined $c[COOKIE_EXPIRES];
  $c[COOKIE_DOMAIN]=scalar reverse $c[COOKIE_DOMAIN] if $c[COOKIE_DOMAIN];

  # Remove any extra fields added in haste
  #
  #splice @c, COOKIE_KEY+1;

  \@c;
}




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
#
sub decode_set_cookie{
  no warnings "experimental";
  # $string, converter
	my $key;
	my $value;
	my @values;
	my $first=1;
  my @fields=split /;\s*/, $_[0];
  #Value needs to be the first field 
	my $count=($values[1], $values[2])=split "=", shift(@fields), 2;

  #If no key value pair the forget it
  return undef if $count!=2;

  # trip whitespace
  $values[1]=trim($values[1]);
  $values[2]=trim($values[2]);

  #If the name is not present forget it
  return unless $values[1]; 
  

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
     /([^,]+), (\d+)\-([^-]{3})\-(\d{4}) (\d+):(\d+):(\d+) (\w+)/;

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

# Encode matching cooki into a cookie string
use feature "signatures";

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



class HTTP::State;

field @_cookies; # An array of cookie 'structs', sorted by the COOKIE_KEY field
field $_suffix_cache :param=undef; #Hash ref used as cache
field $_public_suffix_sub :param=undef;        # Sub used for public suffix lookup.
                            
# Algorithm structures
# Array of arrays acting as key value tuples. Domain sorted in reverse order
#
field @_domain;         #list of [dk, dv ] structure sorted by dk
                        # dv is a array of [pk, pv] which is sorted by pk
                        # pv is array of [cn, ca] which is sorted by cn
field %_sld_cache;
  
BUILD{
}


method second_level_domain{
    unless($_public_suffix_sub){
      require Mozilla::PublicSuffix;  
      $_public_suffix_sub=\&Mozilla::PublicSuffix::public_suffix;
    }

    #search for  prefix 
    my $domain=lc $_[0];
    my $highest;
    my $suffix=$_suffix_cache
      ? $_suffix_cache->{$domain}//=&$_public_suffix_sub
      : &$_public_suffix_sub;
      
    if($suffix){
      substr($domain, -(length($suffix)+1))="";

      if($domain){
        my @labels=split /\./, $domain;
        $highest=pop(@labels).".$suffix";
      }
    }
    $highest;
}

method suffix{
  unless($_public_suffix_sub){
    require Mozilla::PublicSuffix;
    $_public_suffix_sub=\&Mozilla::PublicSuffix::public_suffix;
  }
  $_suffix_cache
    ? $_suffix_cache->{lc $_[0]}//=&$_public_suffix_sub
    : &$_public_suffix_sub;
}









method set_cookies($request_uri, @cookies){

  Log::OK::TRACE and log_trace __PACKAGE__. " set_cookies";

  # Parse the request_uri
  #
  my ($scheme, $authority, $path, $query, $fragment) =
  $request_uri =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

  Log::OK::TRACE and log_trace __PACKAGE__. " authority: ". $authority;

  # Parse the authority into userinfo, host and port
  my ($user, $password, $host, $port)=
    $authority =~  m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

  $port//=80;

  my $time=time-$tz_offset; #Cache time. Translate  to GMT

  # Iterate over the cookies supplied
  for my $c_ (@cookies){
    # Parse or copy the input
    my $c;
    if(ref($c_) eq "ARRAY"){
      # Assume a struct 
      $c=[@$c_];  #Copy
    }
    else {
      # Assume a string
      $c=decode_set_cookie($c_);
    }
    next unless $c;




    # Is this right?
    $scheme ne "https" and next if $c->[COOKIE_SECURE];

    # Set same site to None if not provided
    $c->[COOKIE_SAMESITE]//="None";

    #$c->[COOKIE_SECURE] or next if $c->[COOKIE_SAMESITE];

    ($c->[COOKIE_SECURE] and ($c->[COOKIE_PATH] eq "/") and
    !$c->[COOKIE_DOMAIN]) or next 
      if 0== index($c->[COOKIE_NAME],"__Host-");

    $c->[COOKIE_SECURE] or next 
      if 0==index($c->[COOKIE_NAME], "__Secure-");


    if(defined $c->[COOKIE_MAX_AGE]){

      Log::OK::TRACE and log_trace "max age set: $c->[COOKIE_MAX_AGE]";
      for($c->[COOKIE_MAX_AGE]){
        if($_<=0){
          $c->[COOKIE_EXPIRES]=0; # set to min time
        }
        else{
          $c->[COOKIE_EXPIRES]=$time+$c->[COOKIE_MAX_AGE]; 
          $c->[COOKIE_PERSISTENT]=1;
        }
      }
    }
    elsif(defined $c->[COOKIE_EXPIRES]){
      # Use expiry if exclusivly provided
      #
      for($c->[COOKIE_EXPIRES]){
        $c->[COOKIE_PERSISTENT]=1;
        #parse the date and store in the same field

      }
    }
    else{
      # Session cookie. max out the expiry but mark as non persistent
      #
      $c->[COOKIE_PERSISTENT]=undef;
      $c->[COOKIE_EXPIRES]=$time+400*24*3600; #Mimic chrome for maximum date
    }

    Log::OK::TRACE and log_trace "Expiry set to: $c->[COOKIE_EXPIRES]";


    # Use the host as domain if none specified

    # Process the domain of the cookie. set to default if no explicitly set
    #
    my $rhost=scalar reverse $host;

    if($c->[COOKIE_DOMAIN]){
      # DO a public suffix check on cookies. Need to ensure the domain for the cookie is NOT a suffix

      my $sld=$_sld_cache{$c->[COOKIE_DOMAIN]}//=$self->second_level_domain(scalar reverse $c->[COOKIE_DOMAIN]);


      
      # need to ensure the cookie domain is a sub string of second level domain
      #
      next unless defined $sld;
      $sld=scalar reverse $sld;
      unless(
        0==index($c->[COOKIE_DOMAIN], $sld)
          and (substr($c->[COOKIE_DOMAIN],length($sld),1)||".") eq "."
        ){ 
        Log::OK::TRACE and log_trace "Domain is public suffix. reject";
        next 
      }

      # Also cookie domain needs to be sub string of request host. ie no sub
      # domain. 
      if(
          0==index($rhost, $c->[COOKIE_DOMAIN])
            and (substr($rhost,length($c->[COOKIE_DOMAIN]),1)||".") eq "."
        ){ 
        # Domain must be at least substring (parent domain).
        $c->[COOKIE_HOST_ONLY]=undef;
      }
      else{
        # Ignore cookie. Attempting to set a cookie for a sub domain
        Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie domain invalid";
        next;
      }
    }
    else{
      # Cookie is only accesssable from the same host
      # Set domain to the request host
      $c->[COOKIE_HOST_ONLY]=1;
      $c->[COOKIE_DOMAIN]=$rhost;

    }

    # Process path. default is request url if not provided
    # set default path  as per 5.1.4
    #
    $c->[COOKIE_PATH]//="";
    if( length($c->[COOKIE_PATH])==0 or  substr($c->[COOKIE_PATH], 0, 1) ne "/"){
      # Calculate default
      if(length($path)==0 or substr($path, 0, 1 ) ne "/"){
        $path="/";
      }
      
      # Remove right / if present
      if(length($path) >1){
        my @parts=split "/", $path;
        pop @parts;
        $c->[COOKIE_PATH]=join "/", @parts;
      }
      else {
        $c->[COOKIE_PATH]=$path;
      }
    }
    

    # Here we domain and path match cookies in the store.
    # We DON't want to replace/update existing cookies marked as secure 
    # if the current set_cookie is marked unsecure.
    if(!$c->[COOKIE_SECURE]){
      my @matches=$self->get_cookies("$scheme://".scalar reverse($c->[COOKIE_DOMAIN]).$c->[COOKIE_PATH]);
      next if grep(($_->[COOKIE_SECURE] and $_->[COOKIE_NAME] eq $c->[COOKIE_NAME]), @matches)
    }
    # Set the creation time

    # Set Creation time
    $c->[COOKIE_CREATION_TIME]=$c->[COOKIE_LAST_ACCESS_TIME]=$time;
    Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie creation time: $c->[COOKIE_CREATION_TIME]";


    $c->[COOKIE_KEY]="$c->[COOKIE_DOMAIN] $c->[COOKIE_PATH] $c->[COOKIE_NAME]";

    $c->[COOKIE_MAX_AGE]=undef; # No longer need this

    Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie key: $c->[COOKIE_KEY]";

    my $index=search_string_left $c->[COOKIE_KEY], \@_cookies;
    my $found=$index<@_cookies  && ($_cookies[$index][COOKIE_KEY] eq $c->[COOKIE_KEY]);


    if($found and $c->[COOKIE_EXPIRES]<=$time){
      # Found but expired. Delete the cookie
      Log::OK::TRACE and log_trace __PACKAGE__. " found cookie and expired";
      splice @_cookies, $index, 1;
    }
    elsif($found){
      # Update existing
      #
      Log::OK::TRACE and log_trace __PACKAGE__. " found cookie. Updating";

      # Update creation time of new cookie to match the old cookie
      $c->[COOKIE_CREATION_TIME]=$_cookies[$index][COOKIE_CREATION_TIME];
      $_cookies[$index]=$c;
    }
    elsif($c->[COOKIE_EXPIRES]<$time){
      #Cookie not found and expired

      Log::OK::TRACE and log_trace __PACKAGE__. " no existing cookie, but new expired. Do nothing";

    }
    else {
      # Add  cookie. Push if no cookies, splice if already cookies
      #
      Log::OK::TRACE and log_trace __PACKAGE__. " new cookie name. adding";
      unless(@_cookies){
        push @_cookies, $c;
      }
      else{
        splice @_cookies, $index, 0, $c;
      }
    }
  }
}

# Retrieves the cookies by name, for the $request_uri in question. The actual
# cookies returned are subject to filtering of the user agent conditions.
#
# Referer url is used in selecting cookies for ssame site access
# Policy is a hash of keys modifiying behaviour 
#   eq action=> follow      Like a user clicking a link and navigating to 
#                           a new site 
#                           (Lax and None samesite allow cookies sent) cross origin
#                   
#               resource    user agent loading a resource (ie image )
#                           Not a navigation
#                           (None samesite allows cookies sent) cross origin
#
#               top         Manually typing an address or clicking a shortcut
#                           (Strict samesite) 
#
#               api         Make as an api call, which is a resource call also?
#                           Not a navigation
#

=head3 _get_cookies

Returns a reference to an array of cookie structs matching domain, path, name
etc cookie attributes. Values are references to internal entries so care must
be taken not to manipulate data. 

=cut

method _get_cookies($request_uri, $referer_uri, $action="", $name=""){
  # Cookies are stored sorted in ascending reverse dns order. parse the URI to get the domain
  #
  # Parse the uri

  
  my ($scheme, $authority, $path, $query, $fragment) =
  $request_uri =~ 
    m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

  my ($user, $password, $host, $port)=$authority =~  
    m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

  $port//=80;

  # Look up the suffix. This will be the root for our domain search
  #
  my $sld=scalar reverse $self->suffix($host);
  $host=scalar reverse $host;

  # Parse the uri
  my ($rscheme, $rauthority, $rpath, $rquery, $rfragment) =
  $request_uri =~ 
    m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

    #my ($ruser, $rpassword, $ref_host, $rport)=$authority =~  
    #m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

    #$ref_host=scalar reverse $ref_host;
  
  # Mark as same site if the referer is undefined This is intended to represent
  # top level navigation (typing an address) where the refering site is not
  # considered. this also allows backward compatibility. If your don't provide a
  # referer uri then it is treated as same site and
  my $same_site=defined $referer_uri;
  
  # However if the referer IS defined, test to see if it is the same site
  #
  $same_site||=($rscheme eq $scheme) && ($rauthority eq $authority);



  # Iterate through all cookies until the domain no longer matches
  #
  local $_;
  my $time=time-$tz_offset;
  my @output;
  my $path_ok=1;
  my $run;
  
  # If $name is empty, we are doing a query for all cookies for this domain/path
  my $any_name=!$name;
  my $time_now=time; 

  ####
  # MAIN SEARCH ALGORITHM
  #
  # Search the list from the highest domain down Start of each of matching with
  # search of sorted domain names iterates over the following items until the
  # domain key, substring no longer matches
  #
  #my @levels=split /\./, $host=~s/$sld\.//r;
  my @levels=split /\./, substr $host, length($sld)+1;

  while(@levels){
    $sld="$sld.".shift @levels;
    # Finds the first domain string matching.  The database is searched by the
    # KEY field, which is DOMAIN PATH NAME. The domain is in reverse order so
    # the host name (also reversed) can be used as a prefix which allows a simple 
    # stirng le comparison in the binary search
    #
    my $index=search_string_left $sld, \@_cookies;

    Log::OK::TRACE and log_trace __PACKAGE__. " index is: $index"; 
    Log::OK::TRACE and log_trace  "looking for host: $sld";

    while( $index<@_cookies){
      #say " while in get cookeis index: $index";
      $_=$_cookies[$index];
      #say " sld: $sld, domain: $_->[COOKIE_DOMAIN]";
      # Cookies are sorted by domain. If the domain is not a prefix match
      # we consider the search finished. Actual domain testing is done 
      # if the prefix matches
      #

      # Domains are stored 'reversed'. That means prefixes will always come first.
      # When a  domain no longer matches as a prefix then we know the search can stop
      last if index $sld, $_->[COOKIE_DOMAIN];


      # Need an exact match, not a domain match
      ++$index and next if $host ne $_->[COOKIE_DOMAIN]  and $_->[COOKIE_HOST_ONLY];
      Log::OK::TRACE and log_trace "Hostonly and host eq domain passed";


      # Secure cookie  and secure channel.
      #
      ++$index and next if $_->[COOKIE_SECURE] and $scheme ne "https";
      Log::OK::TRACE and log_trace "secure and scheme eq https passed";

      # Skip this cookies if the action is classed as api and not as a 
      # browing http request
      #
      ++$index and next if $_->[COOKIE_HTTPONLY] and $action//"" eq "api";
      Log::OK::TRACE and log_trace "action passed";


      # Name match Lets see if the cookie name is a match. If so process the
      # expiry immediately. the $any_name flag allows all cookies for a domain to
      # be extracted
      #
      if($any_name or $_->[COOKIE_NAME] eq $name){
        # Found a matching cookie.
        Log::OK::TRACE and log_trace "NAME OK";
        # Process expire
        if($_->[COOKIE_EXPIRES] <= $time){
          # Expired, remove it from the list
          #
          Log::OK::TRACE and log_trace "cookie under test expired. removing";
          splice @_cookies, $index, 1;
          next;
        }

        # Test if we really want to send the cookie to the domain based on use action


        # Check same site?
        # Strict => User agent only send cookie if the referer is of the same domain
        #           Or if the address is typed into the address bar
        #
        # Lax   =>  Clicking a link and the user navigating to a site from an third party is is ok 
        #            However accessing a resource from a thirdparty site the cookie is not sent
        #
        # None  =>   Cookie is always sent for
        #
        if($action){
          # Only process same site if we know what action is being initiated
          #
          if($action eq "top"){
            # Send cookie on for strict, lax or none. Implicit same site
          }
          elsif($action eq "follow"){
            # Send cookie only on lax or none, if not same site.
            ++$index and next unless $same_site || $_->[COOKIE_SAMESITE] =~/Lax|None/i;
             
          }
          elsif($action eq "resource"){
            # eg. Non document non api request. 
            # Only send from third party site if None
            ++$index and next unless $same_site || $_->[COOKIE_SAMESITE] =~/None/i;
          }
          elsif($action eq "api"){
            # Like resource, but is treated as non http
            ++$index and next unless $same_site || $_->[COOKIE_SAMESITE] =~/None/i;
          }
          else {
            # no  action, treat as same site
          }
        }




        # Process path matching as per section 5.1.4 in RFC 6265
        #
        $path||="/";    #TODO find a reference to a standard or rfc for this
        Log::OK::TRACE and log_trace "PATH: $path";
        Log::OK::TRACE and log_trace "Cookie PATH: $_->[COOKIE_PATH]";

        if($path eq $_->[COOKIE_PATH]){
          $path_ok=1;
        }

        elsif (substr($_->[COOKIE_PATH], -1, 1) eq "/"){
          # Cookie path ends in a slash?
          $path_ok=index($path, $_->[COOKIE_PATH])==0  # Yes, check if cookie path is a prefix
        }
        elsif(substr($path,length($_->[COOKIE_PATH]), 1) eq "/"){
          $path_ok= 0==index $path, $_->[COOKIE_PATH];
        }
        else {
          # Not a  path match
          $path_ok=undef;
        }
        Log::OK::TRACE and log_trace "Path ok: $path_ok";

        ++$index and next unless $path_ok; 

        #
        # If we get here, cookie should be included!
        #
        #
        #Update last access time
        #
        $_->[COOKIE_LAST_ACCESS_TIME]=$time_now;
        Log::OK::TRACE and log_trace "Pushing cookie";
        push @output, $_;   

      }
      $index++;
    }
    #say "Last index: $index, size ".@_cookies;
  }
   
  # TODO:
  # Sort the output as recommended by RFC 6525
  #  The user agent SHOULD sort the cookie-list in the following
  #     order:
  #
  #     *  Cookies with longer paths are listed before cookies with
  #        shorter paths.
  #
  #     *  Among cookies that have equal-length path fields, cookies with
  #        earlier creation-times are listed before cookies with later
  #        creation-times.

  @output= sort {
          length($b->[COOKIE_PATH]) <=> length($a->[COOKIE_PATH])
            || $a->[COOKIE_CREATION_TIME] <=> $b->[COOKIE_CREATION_TIME]
      } @output;
  
 
  \@output;

}


method get_cookies($request_uri, $referer_uri=undef, $action=undef, $name=undef){
  # Do a copy of the matching entries
  #
  map [@$_], $self->_get_cookies($request_uri, $referer_uri, $action, $name);
}


method encode_cookies($request_uri, $referer_uri=undef, $action=undef, $name=undef){
  my $cookies=$self->_get_cookies($request_uri, $referer_uri, $action, $name);
  return "" unless @$cookies;
  join "; ", map { "$_->[COOKIE_NAME]=$_->[COOKIE_VALUE]"} @$cookies;

}


method get_kv_cookies($request_uri, $referer_uri=undef, $action=undef, $name=undef){
  
  my $cookies=$self->_get_cookies($request_uri, $referer_uri, $action, $name);
  map(($_->[COOKIE_NAME], $_->[COOKIE_VALUE]), @$cookies);
}


# Mimic HTTP::CookieJar API
# This  should work with HTTP::Tiny for example
# The referer and action are set to defaults
*cookie_header=\*encode_cookies;
*add=\*set_cookies;







method dump_cookies {
  join "\n", map encode_set_cookie($_,1), @_cookies;
}

method db {
  \@_cookies;
}


method slurp_set_cookies($path) {
  open my $file, "<", $path 
    or die "Error opening file $path for reading";

  my $c;
  my $index;
  my $time=time-$tz_offset;

  while(<$file>){
    # Skip if parsing error
    next unless $c=decode_set_cookie($_);
  
    # Don't load if cookie is expired
    #
    next if $c->[COOKIE_EXPIRES]<=$time;

    # Build key for search
    $c->[COOKIE_KEY]="$c->[COOKIE_DOMAIN] $c->[COOKIE_PATH] $c->[COOKIE_NAME]";

    # Do binary search
    #
    $index=search_string_left $c->[COOKIE_KEY], \@_cookies;

    # update the list
    unless(@_cookies){
      push @_cookies, $c;
    }
    else{
      splice @_cookies, $index, 0, $c;
    }
  }
}



method spurt_set_cookies($path){
 open my $file, ">", $path 
  or die "Error opening file for writing";

  my $time=time-$tz_offset;
  for(@_cookies){
    # Ignore session cookies
    #
    next unless $_->[COOKIE_PERSISTENT];

    # Don't save expired cookies
    #
    next if $_->[COOKIE_EXPIRES]<=$time;

    print $file encode_set_cookie($_, 1)."\n";
  }
}

method clear{
  @_cookies=(); #Clear the db
}

1;

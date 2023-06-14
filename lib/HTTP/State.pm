package HTTP::State;
# Please refer to:
# https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes

use feature "say";

our $VERSION="v0.1.0";

# Logging
#
use Log::ger; 
use Log::OK;

# Object system. Will use feature class asap
#
use Object::Pad;

use HTTP::State::Cookie ":all";



# Fast Binary Search subroutines
#
use List::Insertion {type=>"string", duplicate=>"left", accessor=>"->[".COOKIE_KEY."]"};


# Public suffix list list
#
#use Mozilla::PublicSuffix qw<public_suffix>;

# Date 
use Time::Piece;
use Time::Local qw<timegm_modern>;

my $tz_offset=Time::Piece->localtime->tzoffset;

# Encode matching cooki into a cookie string
use feature "signatures";




class HTTP::State;

field @_cookies; # An array of cookie 'structs', sorted by the COOKIE_KEY field
field $_suffix_cache :param=undef; #Hash ref used as cache
field $_public_suffix_sub :param=undef;        # Sub used for public suffix lookup.
field $_default_same_site :param="None";
field $_default_action :param="top";
                            
# Algorithm structures
# Array of arrays acting as key value tuples. Domain sorted in reverse order
#
field @_domain;         #list of [dk, dv ] structure sorted by dk
                        # dv is a array of [pk, pv] which is sorted by pk
                        # pv is array of [cn, ca] which is sorted by cn
field %_sld_cache;
  
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





sub _path_match($path, $cookie){

  # Process path matching as per section 5.1.4 in RFC 6265
  #
  $path||="/";    #TODO find a reference to a standard or rfc for this
  Log::OK::TRACE and log_trace "PATH: $path";
  Log::OK::TRACE and log_trace "Cookie PATH: $_->[COOKIE_PATH]";
  my $path_ok;
  if($path eq $cookie->[COOKIE_PATH]){
    $path_ok=1;
  }

  elsif (substr($cookie->[COOKIE_PATH], -1, 1) eq "/"){
    # Cookie path ends in a slash?
    $path_ok=index($path, $cookie->[COOKIE_PATH])==0  # Yes, check if cookie path is a prefix
  }
  elsif(substr($path,length($cookie->[COOKIE_PATH]), 1) eq "/"){
    $path_ok= 0==index $path, $cookie->[COOKIE_PATH];
  }
  else {
    # Not a  path match
    $path_ok=undef;
  }
  Log::OK::TRACE and log_trace "Path ok: $path_ok";
  $path_ok;
}

#returns self for chaining
# TODO rename to "store_cookies"
method set_cookies($request_uri, @cookies){
  #TODO: fix this
  my $action=$_default_action;
  use Data::Dumper;
  Log::OK::TRACE and log_trace __PACKAGE__. " set_cookies";
  Log::OK::TRACE and log_trace __PACKAGE__. " ".join ", ", caller;
  Log::OK::TRACE and log_trace __PACKAGE__. Dumper @cookies;

  return $self unless @cookies;
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
  SET_COOKIE_LOOP:
  for my $c_ (@cookies){
    # Parse or copy the input
    my $c;
    my $ref=ref $c_;
    if($ref eq "ARRAY"){
      # Assume a struct 
      $c=[@$c_];  #Copy
    }
    else {
      # Assume a string
      $c=decode_set_cookie($c_);
    }
    next unless $c;

    Log::OK::TRACE and log_trace "jar processing ".Dumper $c;
    #1.
    # A user agent MAY ignore a received cookie in its entirety. See Section 5.3.

    #2.
    # If cookie-name is empty and cookie-value is empty, abort these steps
    # and ignore the cookie entirely.
    
    #3.
    # If the cookie-name or the cookie-value contains a %x00-08 / %x0A-1F /
    # %x7F character (CTL characters excluding HTAB), abort these steps and
    # ignore the cookie entirely.


    #4. If the sum of the lengths of cookie-name and cookie-value is more than
    #4096 octets, abort these steps and ignore the cookie entirely
    next if (length($c->[COOKIE_NAME])+ length($c->[COOKIE_VALUE]))>4096;
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 1, 2, 3, 4 OK";

    # 5. Create a new cookie with name cookie-name, value cookie-value. Set the
    #creation-time and the last-access-time to the current date and time.
    $c->[COOKIE_LAST_ACCESS_TIME]=$c->[COOKIE_CREATION_TIME]=$time;
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 5 OK";

    # 6.
    # If the cookie-attribute-list contains an attribute with an attribute-name
    # of "Max-Age":
      # 1.
      # Set the cookie's persistent-flag to true
      #
      # 2. 
      # Set the cookie's expiry-time
      # to attribute-value of the last attribute in the cookie-attribute-list
      # with an attribute-name of "Max-Age".
    #
    # Otherwise, if the cookie-attribute-list contains an attribute with an
    # attribute-name of "Expires" (and does not contain an attribute with an
    # attribute-name of "Max-Age"):
      # 1.
      # Set the cookie's persistent-flag to true.
      #
      # 2.
      # Set the cookie's expiry-time to attribute-value of the last attribute
      # in the cookie-attribute-list with an attribute-name of "Expires".
      #
    #Otherwise:
      # 1.
      # Set the cookie's persistent-flag to false.
      # 
      # 2.
      # Set the cookie's expiry-time to the latest representable date.

    if(defined $c->[COOKIE_MAX_AGE]){
      $c->[COOKIE_PERSISTENT]=1;
      $c->[COOKIE_EXPIRES]=$time+$c->[COOKIE_MAX_AGE]; 
      Log::OK::TRACE and log_trace "max age set: $c->[COOKIE_MAX_AGE]";
    }
    elsif(defined $c->[COOKIE_EXPIRES]){
      $c->[COOKIE_PERSISTENT]=1;
      # expires already in required format 
    }
    else{
      $c->[COOKIE_PERSISTENT]=undef;
      $c->[COOKIE_EXPIRES]=$time+400*24*3600; #Mimic chrome for maximum date

    }

    Log::OK::TRACE and log_trace "Expiry set to: $c->[COOKIE_EXPIRES]";
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 6 OK";

    #7.
    #If the cookie-attribute-list contains an attribute with an attribute-name of "Domain":
      #1.
      #Let the domain-attribute be the attribute-value of the last attribute in
      #the cookie-attribute-list with both an attribute-name of "Domain" and an
      #attribute-value whose length is no more than 1024 octets. (Note that a
      #leading %x2E ("."), if present, is ignored even though that character is
      #not permitted.)
      #
    #Otherwise:
      #1.
      #Let the domain-attribute be the empty string.

    #8.
    #If the domain-attribute contains a character that is not in the range of
    #[USASCII] characters, abort these steps and ignore the cookie entirely.
    #

    #9.
    #If the user agent is configured to reject "public suffixes" and the
    #domain-attribute is a public suffix:
      #1.
      #If the domain-attribute is identical to the canonicalized request-host:
        #1. 
        #Let the domain-attribute be the empty string.
      #Otherwise:
        #1.
        #Abort these steps and ignore the cookie entirely.

      #NOTE: This step prevents attacker.example from disrupting the integrity
      #of site.example by setting a cookie with a Domain attribute of
      #"example".








    # Use the host as domain if none specified

    # Process the domain of the cookie. set to default if no explicitly set
    #
    my $rhost=scalar reverse $host;
    my $sld;
    my $suffix;
    # DO a public suffix check on cookies. Need to ensure the domain for the cookie is NOT a suffix.
    # This means we want a 'second level domain'
    #
    #$sld=$_sld_cache{$c->[COOKIE_DOMAIN]}//=scalar reverse $self->second_level_domain(scalar reverse $c->[COOKIE_DOMAIN]);
    if($c->[COOKIE_DOMAIN]){
      $suffix=$_suffix_cache->{$c->[COOKIE_DOMAIN]}//=scalar reverse $self->suffix(scalar reverse $c->[COOKIE_DOMAIN]);
      Log::OK::TRACE and log_trace "Looking up $c->[COOKIE_DOMAIN]=>$suffix";
      if($suffix){
        if($suffix eq $c->[COOKIE_DOMAIN]){
          Log::OK::TRACE and log_trace "Domain is public suffix. reject";
          next;
        }
        elsif($c->[COOKIE_DOMAIN] eq $rhost){
          $c->[COOKIE_DOMAIN]="";
        }
      }
    }
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 7, 8, 9 OK";

    #10
    #If the domain-attribute is non-empty:
      #If the canonicalized request-host does not domain-match the domain-attribute:
        #1.
        #Abort these steps and ignore the cookie entirely.
      #Otherwise:
        #1
        #Set the cookie's host-only-flag to false.
        #2
        #Set the cookie's domain to the domain-attribute.
    #Otherwise:
      #1
      #Set the cookie's host-only-flag to true.
      #2
      #Set the cookie's domain to the canonicalized request-host.


    if($c->[COOKIE_DOMAIN]){
      if(0==index($rhost, $c->[COOKIE_DOMAIN])){ 
        # Domain must be at least substring (parent domain).
        $c->[COOKIE_HOST_ONLY]=undef;
      }
      else{
        # Reject. no domain match
        Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie domain invalid";
        next;
      }
    }
    else{
      Log::OK::TRACE and log_trace __PACKAGE__. " No domain set for cookie";
      $c->[COOKIE_HOST_ONLY]=1;
      $c->[COOKIE_DOMAIN]=$rhost;
    }
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 10 OK";

    #11.
    #If the cookie-attribute-list contains an attribute with an attribute-name
    #of "Path", set the cookie's path to attribute-value of the last attribute
    #in the cookie-attribute-list with both an attribute-name of "Path" and an
    #attribute-value whose length is no more than 1024 octets. Otherwise, set
    #the cookie's path to the default-path of the request-uri.

    $c->[COOKIE_PATH]//="";
    next if length($c->[COOKIE_PATH])>1024;

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
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 11 OK";
    #12
    #If the cookie-attribute-list contains an attribute with an attribute-name
    #of "Secure", set the cookie's secure-only-flag to true. Otherwise, set the
    #cookie's secure-only-flag to false.

    #13
    #If the scheme component of the request-uri does not denote a "secure"
    #protocol (as defined by the user agent), and the cookie's secure-only-flag
    #is true, then abort these steps and ignore the cookie entirely.


    Log::OK::TRACE and log_trace __PACKAGE__. " Scheme: $scheme action: $action";
    next if $c->[COOKIE_SECURE] and ($scheme ne "https");
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 12, 13 OK";

    #14
    #If the cookie-attribute-list contains an attribute with an attribute-name
    #of "HttpOnly", set the cookie's http-only-flag to true. Otherwise, set the
    #cookie's http-only-flag to false.

    #15
    #If the cookie was received from a "non-HTTP" API and the cookie's
    #http-only-flag is true, abort these steps and ignore the cookie entirely.

    next if ($c->[COOKIE_HTTPONLY] and ($action eq "api"));


    Log::OK::TRACE and log_trace __PACKAGE__. " Step 14, 15 OK";

    #16
    #If the cookie's secure-only-flag is false, and the scheme component of
    #request-uri does not denote a "secure" protocol, then abort these steps
    #and ignore the cookie entirely if the cookie store contains one or more
    #cookies that meet all of the following criteria:
    #
      #1
      #Their name matches the name of the newly-created cookie.
      #2
      #Their secure-only-flag is true.
      #3
      #Their domain domain-matches the domain of the newly-created cookie, or vice-versa.
      #4
      #The path of the newly-created cookie path-matches the path of the existing cookie.
      #
    #Note: The path comparison is not symmetric, ensuring only that a
    #newly-created, non-secure cookie does not overlay an existing secure
    #cookie, providing some mitigation against cookie-fixing attacks. That is,
    #given an existing secure cookie named 'a' with a path of '/login', a
    #non-secure cookie named 'a' could be set for a path of '/' or '/foo', but
    #not for a path of '/login' or '/login/en'.


    if(!$c->[COOKIE_SECURE] and $scheme ne "https"){
      
      # get the second level domain to act as base to start search
      $sld//=$_sld_cache{$c->[COOKIE_DOMAIN]}//=scalar reverse $self->second_level_domain(scalar reverse $c->[COOKIE_DOMAIN]);
      next unless defined $sld;

      my $index=search_string_left $sld, \@_cookies;

      $index=@_cookies if $index<@_cookies  && (index($_cookies[$index][COOKIE_KEY], $sld)==0);
      my $found;
      local $_;
      while(!$found and $index<@_cookies){
        $_=$_cookies[$index];
        #exit the inner loop if the SLD is not a prefix of the current cookie key
        last if index $_->[COOKIE_KEY], $sld;

        next SET_COOKIE_LOOP if $_->[COOKIE_SECURE]
        and $_->[COOKIE_NAME] eq $c->[COOKIE_NAME]    #name match
        and (index($_->[COOKIE_DOMAIN], $sld)==0 or index($sld, $_->[COOKIE_DOMAIN])==0)        # symmetric match
        and _path_match $c->[COOKIE_PATH], $_;    #path match

        $index++;
      }
    }
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 16 OK";

    #17
    #If the cookie-attribute-list contains an attribute with an attribute-name
    #of "SameSite", and an attribute-value of "Strict", "Lax", or "None", set
    #the cookie's same-site-flag to the attribute-value of the last attribute
    #in the cookie-attribute-list with an attribute-name of "SameSite".
    #Otherwise, set the cookie's same-site-flag to "Default".

    $c->[COOKIE_SAMESITE]//=$_default_same_site;

    Log::OK::TRACE and log_trace __PACKAGE__. " Step 17 OK";
    #18
    #If the cookie's same-site-flag is not "None":
      #1
      #If the cookie was received from a "non-HTTP" API, and the API was called
      #from a navigable's active document whose "site for cookies" is not
      #same-site with the top-level origin, then abort these steps and ignore
      #the newly created cookie entirely.
      #2
      #If the cookie was received from a "same-site" request (as defined in
      #Section 5.2), skip the remaining substeps and continue processing the
      #cookie.
      #3
      #If the cookie was received from a request which is navigating a
      #top-level traversable [HTML] (e.g. if the request's "reserved client" is
      #either null or an environment whose "target browsing context"'s
      #navigable is a top-level traversable), skip the remaining substeps and
      #continue processing the cookie.
      #
      #Note: Top-level navigations can create a cookie with any SameSite value,
      #even if the new cookie wouldn't have been sent along with the request
      #had it already existed prior to the navigation.
      #4
      #Abort these steps and ignore the newly created cookie entirely.
      #my $action="top";
    my $same_site;
    #my $same_site= defined $referer_uri
    #  ? ($rscheme eq $scheme) && ($rauthority eq $authority)
    #  : 1;

    if($c->[COOKIE_SAMESITE] ne "None"){
      if($action eq "api" and !$same_site){
        next;
      }
      elsif($action eq "follow" and $same_site){
        #Continue
      }
      elsif($action eq "resource" and $same_site){
        #Continue
      }
      elsif($action eq "top"){
        #Continue
      }
      else {
        next;
      }
    }

    Log::OK::TRACE and log_trace __PACKAGE__. " Step 18 OK";

    #19
    #If the cookie's "same-site-flag" is "None", abort these steps and ignore
    #the cookie entirely unless the cookie's secure-only-flag is true.
    Log::OK::TRACE and log_trace __PACKAGE__. Dumper encode_set_cookie $c;
    next if $c->[COOKIE_SAMESITE] eq "None" and !$c->[COOKIE_SECURE];

    Log::OK::TRACE and log_trace __PACKAGE__. " Step 19 OK";

    #20
    #If the cookie-name begins with a case-insensitive match for the string
    #"__Secure-", abort these steps and ignore the cookie entirely unless the
    #cookie's secure-only-flag is true.
    #
    next if $c->[COOKIE_NAME]=~/^__Secure-/i and !$c->[COOKIE_SECURE];

    Log::OK::TRACE and log_trace __PACKAGE__. " Step 20 OK";

    #21
    #If the cookie-name begins with a case-insensitive match for the string
    #"__Host-", abort these steps and ignore the cookie entirely unless the
    #cookie meets all the following criteria:
      #1
      #The cookie's secure-only-flag is true.
      #2
      #The cookie's host-only-flag is true.
      #3
      #The cookie-attribute-list contains an attribute with an attribute-name
      #of "Path", and the cookie's path is /.

    next if $c->[COOKIE_NAME]=~/^__Host-/i and !($c->[COOKIE_SECURE] and
      ($c->[COOKIE_PATH] eq "/") and $c->[COOKIE_HOST_ONLY]);

    Log::OK::TRACE and log_trace __PACKAGE__. " Step 21 OK";

    #22
    #If the cookie-name is empty and either of the following conditions are
    #true, abort these steps and ignore the cookie:
      #1
      #the cookie-value begins with a case-insensitive match for the string
      #"__Secure-"
      #2
      #the cookie-value begins with a case-insensitive match for the string
      #"__Host-"
    next if !$c->[COOKIE_NAME] and ($c->[COOKIE_VALUE]=~/^__Host-/i or $c->[COOKIE_VALUE]=~/^__Secure-/i);

    Log::OK::TRACE and log_trace __PACKAGE__. " Step 22 OK";
 
    #23
    #If the cookie store contains a cookie with the same name, domain,
    #host-only-flag, and path as the newly-created cookie:
      #1
      #Let old-cookie be the existing cookie with the same name, domain,
      #host-only-flag, and path as the newly-created cookie. (Notice that this
      #algorithm maintains the invariant that there is at most one such
      #cookie.)
      #2
      #If the newly-created cookie was received from a "non-HTTP" API and the
      #old-cookie's http-only-flag is true, abort these steps and ignore the
      #newly created cookie entirely.
      #3
      #Update the creation-time of the newly-created cookie to match the creation-time of the old-cookie.
      #4
      #Remove the old-cookie from the cookie store.

    #24
    #Insert the newly-created cookie into the cookie store.
    #A cookie is "expired" if the cookie has an expiry date in the past.

    #The user agent MUST evict all expired cookies from the cookie store if, at
    #any time, an expired cookie exists in the cookie store.
    
    #At any time, the user agent MAY "remove excess cookies" from the cookie
    #store if the number of cookies sharing a domain field exceeds some
    #implementation-defined upper bound (such as 50 cookies).

    #At any time, the user agent MAY "remove excess cookies" from the cookie
    #store if the cookie store exceeds some predetermined upper bound (such as
    #3000 cookies).

    #When the user agent removes excess cookies from the cookie store, the user
    #agent MUST evict cookies in the following priority order:

      #1
      #Expired cookies.
      #2
      #Cookies whose secure-only-flag is false, and which share a domain field
      #with more than a predetermined number of other cookies.
      #3
      #Cookies that share a domain field with more than a predetermined number
      #of other cookies.
      #4
      #All cookies.
      #
    #If two cookies have the same removal priority, the user agent MUST evict
    #the cookie with the earliest last-access-time first.

  #When "the current session is over" (as defined by the user agent), the user
  #agent MUST remove from the cookie store all cookies with the persistent-flag
  #set to false.




    # Build key to perform binary search in database. This key is unique in the database
    #
    $c->[COOKIE_KEY]="$c->[COOKIE_DOMAIN] $c->[COOKIE_PATH] $c->[COOKIE_NAME] $c->[COOKIE_HOST_ONLY]";
    $c->[COOKIE_MAX_AGE]=undef; # No longer need this, so 
    Log::OK::TRACE and log_trace __PACKAGE__."::set_cookie key: $c->[COOKIE_KEY]";

    # Lookup in database
    #Index of left side insertion
    my $index=search_string_left $c->[COOKIE_KEY], \@_cookies;

    #Test if actually found or just insertion point
    my $found=$index<@_cookies  && ($_cookies[$index][COOKIE_KEY] eq $c->[COOKIE_KEY]);

    if($found){
        #reject if api call http only cookie currently exists
        next if $_cookies[$index][COOKIE_HTTPONLY] and $action eq "api";
        $c->[COOKIE_CREATION_TIME]=$_cookies[$index][COOKIE_CREATION_TIME];
        if($c->[COOKIE_EXPIRES]<=$time){
          # Found but expired by new cookie. Delete the cookie
          Log::OK::TRACE and log_trace __PACKAGE__. " found cookie and expired";
          splice @_cookies, $index, 1;
        }
    }

    elsif($c->[COOKIE_EXPIRES]<$time){
      next; # new cookie already expired.
    }
    else {
          # insert new cookie
          Log::OK::TRACE and log_trace __PACKAGE__. " new cookie name. adding";
          unless(@_cookies){
            push @_cookies, $c;
          }
          else{
            Log::OK::TRACE and log_trace __PACKAGE__. " new cookie name. adding";
            splice @_cookies, $index, 0, $c;
          }
    }
    Log::OK::TRACE and log_trace __PACKAGE__. " Step 23, 24 OK";
  }
  return $self;
}


# Retrieves the cookies by name, for the $request_uri in question. The actual
# cookies returned are subject to filtering of the user agent conditions.
#
# Referer url is used in selecting cookies for ssame site access
# Policy is a hash of keys modifiying behaviour 
#   eq action=> follow/navigate
#                 HTTP only
#                   true
#                 Trigger:
#                   User clicking a link and navigating to a new site
#
#                 Samesite handling:
#                   Lax and None - allow cookies sent cross origin
#                   Strict - no cookies sent
#                   
#               resource    
#                 HTTP only
#                   true
#                   Not a navigation
#                 Trigger:
#                   User agent parsing a html file and loading refereced resouces (ie image)
#                 Samesite handling
#                   None - allows cookies sent cross origin
#                   Lax - no cookie sent
#                   Strict - no cookie sent
#
#
#               top
#                 HTTP only
#                   true
#                 Trigger:
#                   Manually typing an address or clicking a shortcut
#
#                 Samesite handling:
#                     Strict - cookie sent
#                     Lax - cookie sent
#                     None - cookie sent
#
#               api
#                 HTTP only
#                   false - only send cookie if HTTPonly false
#                   Not a navigation
#                 Trigger:
#                   programic access
#
#                 Samesite
#                   same as resource
#

method _get_cookies($request_uri, $referer_uri="", $action="", $name=""){
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
  $referer_uri =~ 
    m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

    #my ($ruser, $rpassword, $ref_host, $rport)=$authority =~  
    #m|(?:([^:]+)(?::([^@]+))@){0,1}([^:]+)(?::(\d+)){0,1}|x;

    #$ref_host=scalar reverse $ref_host;
  
  # Mark as same site if the referer is undefined This is intended to represent
  # top level navigation (typing an address) where the refering site is not
  # considered. this also allows backward compatibility. If your don't provide a
  # referer uri then it is treated as same site and
  #
  # However if the referer IS defined, test to see if it is the same site
  my $same_site= defined $referer_uri
    ? ($rscheme eq $scheme) && ($rauthority eq $authority)
    : 1;
  



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
    # string le comparison in the binary search
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
      #last if index $sld, $_->[COOKIE_DOMAIN];
      last if index $_->[COOKIE_DOMAIN], $sld;


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
        #$path_ok=
        ++$index and next unless _path_match($path, $_);
        ##########################################################################################
        # $path||="/";    #TODO find a reference to a standard or rfc for this                   #
        # Log::OK::TRACE and log_trace "PATH: $path";                                            #
        # Log::OK::TRACE and log_trace "Cookie PATH: $_->[COOKIE_PATH]";                         #
        #                                                                                        #
        # if($path eq $_->[COOKIE_PATH]){                                                        #
        #   $path_ok=1;                                                                          #
        # }                                                                                      #
        #                                                                                        #
        # elsif (substr($_->[COOKIE_PATH], -1, 1) eq "/"){                                       #
        #   # Cookie path ends in a slash?                                                       #
        #   $path_ok=index($path, $_->[COOKIE_PATH])==0  # Yes, check if cookie path is a prefix #
        # }                                                                                      #
        # elsif(substr($path,length($_->[COOKIE_PATH]), 1) eq "/"){                              #
        #   $path_ok= 0==index $path, $_->[COOKIE_PATH];                                         #
        # }                                                                                      #
        # else {                                                                                 #
        #   # Not a  path match                                                                  #
        #   $path_ok=undef;                                                                      #
        # }                                                                                      #
        # Log::OK::TRACE and log_trace "Path ok: $path_ok";                                      #
        ##########################################################################################

        #++$index and next unless $path_ok; 

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


#TODO rename to retrieve_cookies?
method encode_request_cookies($request_uri, $referer_uri=undef, $action=undef, $name=undef){
  my $cookies=$self->_get_cookies($request_uri, $referer_uri, $action, $name);
  return "" unless @$cookies;
  join "; ", map { "$_->[COOKIE_NAME]=$_->[COOKIE_VALUE]"} @$cookies;

}


method get_kv_cookies($request_uri, $referer_uri=undef, $action=undef, $name=undef){
  
  my $cookies=$self->_get_cookies($request_uri, $referer_uri, $action, $name);
  map(($_->[COOKIE_NAME], $_->[COOKIE_VALUE]), @$cookies);
}









method dump_cookies {
  map encode_set_cookie($_, 1), @_cookies;
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
    $c->[COOKIE_KEY]="$c->[COOKIE_DOMAIN] $c->[COOKIE_PATH] $c->[COOKIE_NAME] $c->[COOKIE_HOST_ONLY]";

    # Do binary search
    #
    $index=search_string_left $c->[COOKIE_KEY], \@_cookies;

    # update the list
    unless(@_cookies){
      push @_cookies, $c;
    }
    else{
      # If the key is identical, then we prefer the latest cookie,
      # TODO: Fix key with scheme?
      my $replace= ($_cookies[$index][COOKIE_KEY] eq $c->[COOKIE_KEY])
        ? 1
        : 0;

      splice @_cookies, $index, $replace, $c;
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

# Returns self for chaining
method clear{
  @_cookies=(); #Clear the db
  $self;
}


# Compatibility matrix
# HTTP::CookieJar
#   Additional api
#   new
#     create a new jar
#   clear
#     empty the jar
#   dump_cookies
#     
#
# Used by:
#   HTTP::Tiny
#   FURL
#  Expected API
#   $jar->add($url, $set_cookie_string)
#     Parse set cookie string and add cookie to jar
#
#   #jar->cookie_header($url)
#     Retrieve cookies from jar and serialize for header

# The referer and action are set to defaults
*cookie_header=\*encode_request_cookies;
*add=\*set_cookies;
1;

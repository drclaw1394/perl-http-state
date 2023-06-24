# NAME

HTTP::State - RFC6265bis-draft Cookie Jar for HTTP Clients

# SYNOPSIS

```perl
use HTTP::State ":flags";
 
# Create a jar. Default flags for compatibility API.
#
my $jar=HTTP::State->new(default_flags=>FLAG_TYPE_HTTP|FLAG_TOP_LEVEL|...);

# Requested URL
#
my $request_url="http://test.example.com";



# Retrieve encoded cookies name/values applicable for the request. User agent
# indicates the context of the request using flags.
#
my $flags=FLAGS_TYPE_HTTP|FLAGS_TOP_LEVEL|...;
my $cookie_header = $jar->retrieve_cookies($request_url, $flags);

#       OR 

# use the  HTTP::CookieJar compatible API, jar's default flags
#
my $cookie_header = $jar->cookie_header($request_url);




# Do a request...
#
my $response=user_agent->get(cookie_header=>$cookie_header);




# Store the  Set-Cookies in the jar for the request url w
#
$jar->store_cookies($request_url, $flags, $response->header->{Set_Cookie});

#     OR

# use the HTTP::CookieJar compatible API, using the default flags
$jar->add($request_url, $response->header->{Set_Cookie});
```

# DESCRIPTION

An up to date cookie processing module, implementing a RFC6265bis-draft based
"cookie jar" for HTTP user agents.  At the time of writing the current draft is
'12'. As the RFC progresses this module will be updated accordingly.

A summary of cookie handling benefits from RFC6265bis-draft include: 

- Public suffix checking
- Prefix cookie name processing
- Restricted upper limit of expiry dates
- same site status
- API or HTTP
- safe method
- top level navigation

Default importing of the module does not import any symbols. If you intend to
use the extended RFC6265bis-draft features directly, please import with
":flags" parameter for bit field masks.

For explicit encoding and decoding of cookie strings (not via a cookie jar),
please see the companion [HTTP::State::Cookie](https://metacpan.org/pod/HTTP%3A%3AState%3A%3ACookie) module. This is used internally
for encoding and decoding cookies.

# SAMESITE and CONTEXT

It is necessary the user agent performs additional book keeping and testing
of what is a 'same site' request, top level navigation, reloading, document etc
to fully utilise the additional functionality available in this module.

While these tests/conditions are specified in RFC6265bis-draft, it is not in
the scope of this module and needs to be implemented in a user-agent.  The
results of such tests are represented as bit fields, which are used to guide
the store/retrieve algorithm accordingly within this module.

# COMPATIBILITY

A compatibility interface matching that of  [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) is available to
aid in adoption of this module.

This in theory should allow user-agents like [HTTP::Tiny](https://metacpan.org/pod/HTTP%3A%3ATiny) and [Furl](https://metacpan.org/pod/Furl) for
example to benefit from performance and security improvements with limited
changes to existing code.

To work around the lack of same site / browsing context support in the
[HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) API, the compatibility API utilises the current values of
the 'default flags' for the cookie jar. 

# API

## User Agent Context Flags

Flags are used to mark the intent of a request initiated by a user-agent. 

### FLAG\_SAME\_SITE

When this flag is set, request is considered "same-site". When unset, request
is considered "cross-site".

### FLAG\_TYPE\_HTTP

When this flag is set, request is considered "HTTP". When unset, request is
considered "non-HTTP".

### FLAG\_SAFE\_METH

When this flag is set, request is considered "safe". When unset, request is
considered "unsafe".

### FLAG\_TOP\_LEVEL

When this flag is set, request is considered "top level". When unset, request
is considered "not-top-level".

## Createing a cookie jar

### new

```perl
my $jar=HTTP::State->new(...);
```

Creates a new cookie jar object. Optional named arguments can be provided:

- default\_flags

    ```perl
    my $jar=HTTP::State->new(default_flags=>flags);
    ```

    Sets the default flags used for storing and retrieving cookies, when no defined
    value is provided via `retrieve_cookies` and `store_cookies`

    Is also the value used in the compatibility API

    Default is all flags on
    (FLAG\_TYPE\_HTTP|FLAG\_TOP\_LEVEL|FLAG\_SAME\_SITE|FLAG\_SAFE\_METH).

- retrieve\_sort

    ```perl
    my $jar=HTTP::State->new(retrieve_sort=>1||0);
    ```

    A boolean enabling sorting of retrieved cookies by path length and creation
    time.

    Default is false (no sorting).

- max\_expiry

    ```perl
    my $jar=HTTP::State->new(max_expiry=>seconds);
    ```

    The upper limit in duration a cookie can be valid for.  Value is in seconds.

    Default is 400 days (400 \* 24\* 3600)

- lax\_allowing\_unsafe

    ```perl
    my $jar=HTTP::State->new(lax_allowing_unsafe=>1||0)
    ```

    A boolean enabling retrieval of cookies for unsafe methods  and default same
    site, as long as cookie is no older than `lax_allow_unsafe_timeout`

    The default value is false.

- lax\_allowing\_unsafe\_timeout

    ```perl
    my $jar=HTTP::State->new(lax_allowing_unsafe_timeout=>seconds)
    ```

    The timeout value (age) to use when testing the `lax_allow_unsafe_timeout`.

    The default value is 120 seconds

- public\_suffix\_sub

    ```perl
    my $jar=HTTP::State->new(public_suffix_sub=>sub {...});
    ```

    A code reference which performs public suffix lookup on a URI.  The code ref
    must take a domain name as an argument and return a suffix or empty string
    string if no suffix exists.

    If this option is not provided, a reference to  the `public_suffix` routine
    from [Mozilla::PublicSuffix](https://metacpan.org/pod/Mozilla%3A%3APublicSuffix) is used.

## Storing and Retrieving

For new code, these methods are preferred over the compatibility API, to make
better use of 'browsing context'.

### store\_cookies

```
$jar->store_cookies($request_uri, $flags, $string_or_struct, ...);
```

Takes a `$request_url` , browsing context `$flags` and one or more Set-Cookie
header string values **or** cookie\_structs. Stores them in the cookie jar as per
the 'storage model' of RFC6265bis-draft.

The exact processing of the cookies is subject to the `$flags` bit field,
which is a combination of the 'context flags'. If set to `undef` the current
default bit flags for the cookie jar will be used.

This method in intended to be called from a user-agent on receipt of a HTTP
response.

### retrieve\_cookies

```
$jar->retrieve_cookies($request_url, $flags); 
```

Retrieves cookies from a jar, for the specified `$request_url` according to
RFC6265bis-draft 'cookie retrieval'. The cookies are encodes them into a string
suitable for use in a Cookie header in a HTTP request.

The exact processing of the cookies is subject to the `$flags` bit field,
which is a combination of the 'context flags'. If set to `undef` the current
default bit flags for the cookie jar will be used.

This method in intended to be called from a user-agent in generation of a HTTP
request.

## Auxillary

### get\_cookies

```
$jar->get_cookies($request_url);
$jar->get_cookies($request_url, $flags); 
```

Takes the same arguments as `retrieve_cookies` and matches the same cookies.
Returns a copied list of the matched cookie structures instead of a encoded
string.

### get\_kv\_cookies

```
$jar->get_kv_cookies($request_url);
$jar->get_kv_cookies($request_url, $same_site_status, $type, $safe);
```

Takes the same arguments as `retrieve_cookies` and matches the same cookies.
Returns a list of key value pairs, of names and values.

## HTTP::CookieJar Compatibility Interface

These methods of the same name an intent as those found in [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar).
There are most certainly minor differences, but should allow a [HTTP::State](https://metacpan.org/pod/HTTP%3A%3AState)
cookie jar to be a drop in replacement in most circumstances a
[HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) is used. 

### add

```
$jar->add($url, $set_cookie_string);
```

Adds a cookie (as a Set\_Cookie value string `$set_cookie_string`) to the
cookie jar for the request URL `$url`. 

**Note on SAME SITE:** It is a compatibility wrapper around `store_cookies`
utilising the default flags for the jar as no flags for same site support can
be supplied directly.

Please refer to the [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) for further information.

### clear

```
$jar->clear;
```

Removes all cookies from the jar

### cookies\_for

```
$jar->cookies_for($url);
$jar->cookies_for($url);
```

Returns a list of hash refs representing a set cookie for a target `$url`. The
elements of each hash are named as per [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar). Additional elements
could also exist (IE samesite)

Please refer to the [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) for further information.

### cookie\_header

```
$jar->cookie_header($url)
```

Retrieves any applicable cookies for the target `$url`, and encodes into a
Cookie header string value.

**Note on SAME SITE:** It is a compatibility wrapper around
`retrieve_cookies` utilising the default flags for the jar, as no flags
for same site support can be supplied directly.

Please refer to the [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) for further information.

### dump\_cookies

```perl
$jar->dump_cookies;
$jar->dump_cookies({persistent => 1});
```

Returns a list of strings encoded as Set Cookie values, but with additional
internal information.  The `{persistent => 1}` parameter forces only
persistent cookies to be processed, ignoring session cookies.  

Adjusts the creation and last access times to be relative to epoch in the local
time, instead of GMT for interoperability with [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar). 

### load\_cookies

```
$jar->load_cookies(@cookies)
```

Takes a list of Set-Cookie type strings written out previous with
`dump_cookies` and injects them into the cookie jar.

Decodes the creation time and last access time expected in local timezone
seconds. 

Please refer to the [HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) for further information.

# Algorithm

Some specific design tricks are used to improve the storage and retrieval
process compared to other cookie jars.

- Keyed

    Cookies are uniquely identified by the domain, path, name and  host only flag
    (as per RFC6265bis-draft). These are combined into a key, which make it easy to
    sort

- Reversed Domain Names

    The domain value (in the key and domain field) is stored in reverse, allowing
    the use of `index` to do domain matching of the key directly as  prefix instead of a suffix.

- Cached public suffix

    Public suffix lookups are cached and also stored in reverse for direct
    substring comparison to domains.

- Binary Search

    Sorting and searching of the cookies is done firstly by 'second level domain'
    of a request URL using binary search provided by [List::Insertion](https://metacpan.org/pod/List%3A%3AInsertion)

- Preresolved subroutine references

    The main retrieval subroutine is an anonymous sub instead of a method, for
    better argument reuse and no unneeded dynamic lookup.

# PERFORMANCE

Cookie retrieval (100 random cookies added):

```
                 Rate http_cookiejar     http_state  protocol_http
http_cookiejar 58.0/s             --           -96%           -97%
http_state     1614/s          2682%             --           -19%
protocol_http  1987/s          3325%            23%             --
```

# TODO

Encode jar to other formats

# COMPARISON TO OTHER MODULES

[Protocol::HTTP::CookieJar](https://metacpan.org/pod/Protocol%3A%3AHTTP%3A%3ACookieJar) is a very fast cookie jar module, also
implementing RFC6265bis-draft, though it requires a large number of XS modules
to get going.

[HTTP::CookieJar](https://metacpan.org/pod/HTTP%3A%3ACookieJar) is the cookie jar suggested in the [LWP](https://metacpan.org/pod/LWP) documentation.
While it has public suffix support, it doesn't provide the additional
conditions of RFC6265bis-draft. It is also quite slow in comparison to this
module.

# AUTHOR

Ruben Westerberg, <drclaw@mac.com>

# COPYRIGHT AND LICENSE

Copyright (C) 2023 by Ruben Westerberg

Licensed under MIT

# DISCLAIMER OF WARRANTIES

THIS PACKAGE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE.

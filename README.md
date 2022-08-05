[![builds.sr.ht status](https://builds.sr.ht/~panda-roux/MoonGem.svg)](https://builds.sr.ht/~panda-roux/MoonGem?)

# MoonGem

## Introduction

MoonGem is a Gemini protocol server written in C. It supports serving static files as well as Gemtext (.gmi) files with inline Lua scripting.

An example page might look like this:

```
# Example 1

Lua scripts are enclosed by double curly-braces.

{{ for i = 1, 10 do mg.line(i) end }}


# Example 2

If a script returns a string, that string will be written to the page verbatim.

{{ return "Meow!" }}


# Example 3

{{
  mg.head("Script blocks may span multiple lines", 2)
  mg.line("There are several methods that modify response headers")
  mg.set_language("en-US")
}}
```

## Dependencies

- OpenSSL 1.1.1 or later
- Lua 5.4 (5.3 may work but I haven't tried it)
- LibMagic
- LibEvent 2.1

## Installation

```
git clone https://git.panda-roux.dev/MoonGem
cd MoonGem && git submodule update --init
cmake -B build . && cd build
make && sudo make install
```

## Usage

```
Usage: moongem [options] --cert=cert.pem --key=key.pem
   or: moongem [options] -c cert.pem -k key.pem

A Gemini server with inline Lua scripting for generating dynamic content

    -h, --help            show this help message and exit

Cryptography
    -c, --cert=<str>      (required) certificate file path (.pem)
    -k, --key=<str>       (required) key file path (.pem)

Network
    -p, --port=<int>      port to listen for Gemini requests on (default: 1965)

Content
    -r, --root=<str>      root directory from which to serve content (default: current)
    -c, --chunk=<int>     size in bytes of the chunks loaded into memory while serving static files (default: 16384)

Middleware
    -b, --before=<str>    script to be run before each request is handled
    -a, --after=<str>     script to be run after a request has resulted in a success response code (20)
    -e, --error=<str>     script to be run after a request has resulted in an error response code (40 thru 59)
```

## API

The start and end of script sections are indicated with a double curly-braces.
- Start: `{{`
- End: `}}`

All of the MoonGem-defined functionality is contained within a table called `mg`.

### Pre-Request

These methods are only accessible from pre-request scripts.

- `mg.set_path([new-path])`
    - Overrides the incoming request path with a new value, or `/` if one is not provided
    - This can be useful for implementing virtual directories and other URL-reinterpretation features
- `mg.set_input([new-input])`
    - Overrides the incoming request's input string, or removes it if no new value is provided
- `mg.interrupt()`
    - Instructs MoonGem to bypass the rest of the requet-handling pipeline and use the current response state
    - Unless otherwise set, the default response status code will be 20 (OK)

### Body

These methods modify the body of the Gemini page.

- `mg.include(<file-path>)`
    - Inserts the contents of the file at <file-path> into the page verbatim
    - The file is not processed in any way
- `mg.write(<text>)`
    - Writes `text` to the page
- `mg.line([text])`
    - Writes `text` to the page followed by a line break
- `mg.link(<url>, [text])`
    - Writes a link to `url` on the page, and optionally includes the alt-text `text`
- `mg.head(<text>, [level])`
    - Writes a header line containing `text` to the page, with an optional header level
    - The default header level is 1 (i.e. a single '#' character)
- `mg.quote(<text>)`
    - Writes `text` in a quotation line to the page
- `mg.block(<text>)`
    - Writes `text` in a preformatted block to the page
- `mg.begin_block([alt-text])`
    - Writes the beginning of a preformatted block to the page, with optional `alt-text`
- `mg.end_block()`
    - Writes the end of a preformatted block to the page
    - Should follow `mg.begin_block`

### Header

These methods modify the response header.

If a method is called which modifies the response's status code (which all but the first of these do), then no further scripts will be run and the server will send the response immediately.

- `mg.set_language(<language>)`
    - Sets the `lang` portion of the response header, indicating the language(s) that the page is written in
- `mg.set_mimetype(<mimetype>)`
    - Sets the response mimetype string, indicating the type of content being delivered.  The default for gemtext documents is `text/gemini; charset=utf-8`.
- `mg.success()`
    - Sets the response status code to 20 (OK)
    - Only really useful in pre- and post-request scripts
- `mg.temp_redirect(<url>)`
    - Responds with a code-30 temporary redirect to `url`
- `mg.redirect(<url>)`
    - Responds with a code-31 redirect to `url`

- The following methods each causes the server to respond with one of the status codes in the 40 to 60 range.    An optional `meta` string may be appended to the response in order to provide the client with more information.
    - `mg.temp_failure([meta])`
    - `mg.unavailable([meta])`
    - `mg.cgi_error([meta])`
    - `mg.proxy_error([meta])`
    - `mg.slow_down([meta])`
    - `mg.failure([meta])`
    - `mg.not_found([meta])`
    - `mg.gone([meta])`
    - `mg.proxy_refused([meta])`
    - `mg.bad_request([meta])`
    - `mg.cert_required([meta])`
    - `mg.unauthorized([meta])`

### Input

These methods are concerned with handling user-input.

- `mg.get_path()`
    - Returns the path portion of the requested URL
    - This path is standardized to include a default document (index.gmi) if one is not present (see get_raw_path)
- `mg.get_raw_path()`
    - Returns the path as requested by the client, prior to standardization
- `mg.get_input([meta])`
    - If an input argument was included in the request URL, this method returns that value
    - If no input was provided in the request, then the server responds with a code-10 status response and optional `meta` string
- `mg.get_sensitive_input([meta])`
    - Same as `mg.get_input`, but uses status code 11
    - Client support for this is status code is not guaranteed
- `mg.has_input()`
    - Returns `true` if there was an input argument included in the request
    - Otherwise returns `false`

### Certificate

- `mg.get_cert([meta])`
    - If a client certificate was provided along with the request, then a table with the following members is returned:
        - `fingerprint`: a string representing an SHA256 hash of the certificate's modulus in hexadecimal format
        - `not_after`: a unix timestamp representing the expiration time of the certificate
    - If no client certificate was provided with the request, then the server responds with a code-60 status and optional `meta` string
        - If client certificates are an optional feature of your application, use `mg.has_cert` to check whether one exists before calling this method in order to avoid the code-60 response
    - TODO: fetch additional fields from the cert (CN, etc.)
- `mg.has_cert()`
    - Returns `true` if a client certificate was included along with the request
    - Otherwise returns `false`

### Key/Value Store

MoonGem implements an in-memory key/value store accessed via the `mg.store` table.  This feature is useful for establishing state that's persistent across multiple requests.

- `#mg.store`
  - Returns the number of stored key/value pairs
- `mg.store.dump([path])`
  - Writes the contents of the data store in a tab-separated format to a file at `path`, or stdout if `path` is ommitted
- `mg.store.get_info()`
  - Returns a table with the following fields:
    - `length`: The number of stored key/value pairs
    - `capacity`: The total number of slots allocated
    - `data_size`: The combined length of all of the stored values, in bytes

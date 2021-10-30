[![builds.sr.ht status](https://builds.sr.ht/~panda-roux/MoonGem.svg)](https://builds.sr.ht/~panda-roux/MoonGem?)

# MoonGem

## Introduction

MoonGem is a Gemini protocol server written in C. It supports serving static files as well as Gemtext (.gmi) files with inline Lua scripting.

Script blocks are denoted using special begin/end line tokens. An example page might look like this:

```
# Example 1

Lua scripts are enclosed by double curly-braces.

{{ for i = 1, 10 do line(i) end }}


# Example 2

If a script returns a string, that string will be written to the rendered gemtext as-is.

{{ return "Meow!" }}


# Example 3

{{
  head("Script blocks may span multiple lines.")
  line("There are several methods that modify response headers")
  set_language("en-US")
}}
```

## Dependencies

OpenSSL 1.1.1 or later
Lua 5.4 (5.3 may work but I haven't tried it)
LibMagic
LibEvent 2.1

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
```

## API

The start and end of script sections are indicated with a double curly-braces.
- Start: `{{`
- End: `}}`

A single global variable PATH contains the path of the requested page (i.e. /some/path/index.gmi).

All of the MoonGem-defined methods listed below are contained within a table called `mg`.

### Body

- include(<file-path>)

- write(<text>)

- line([text])

- link([text])

- head(<text>, [level])

- quote(<text>)

- block(<text>)

- begin_block([alt-text])

- end_block()

### Header

- set_language(<language>)

- temp_redirect(<url>)

- redirect(<url>)

- temp_failure([meta])

- unavailable([meta])

- cgi_error([meta])

- proxy_error([meta])

- slow_down([meta])

- failure([meta])

- not_found([meta])

- gone([meta])

- proxy_refused([meta])

- bad_request([meta])

- cert_required([meta])

- unauthorized([meta])

### Input

- get_input([meta])

- get_sensitive_input([meta])

- has_input()

### Certificate

- get_cert([meta])

- has_cert()

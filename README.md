[![builds.sr.ht status](https://builds.sr.ht/~panda-roux/MoonGem.svg)](https://builds.sr.ht/~panda-roux/MoonGem?)

# MoonGem

## Introduction

MoonGem is a Gemini protocol server written in C. It supports serving static files as well as Gemtext (.gmi) files with inline Lua scripting.

Script blocks are denoted using special begin/end line tokens. An example page might look like this:

```
# Example 1

Lua scripts are enclosed by double curly-braces.

{{ for i = 1, 10 do mg.line(i) end }}


# Example 2

If a script returns a string, that string will be written to the rendered gemtext as-is.

{{ return "Meow!" }}


# Example 3

{{
  mg.head("Script blocks may span multiple lines.")
  mg.line("There are several methods that modify response headers")
  mg.set_language("en-US")
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

All of the MoonGem-defined functionality is contained within a table called `mg`.

### Body

- mg.include(<file-path>)

- mg.write(<text>)

- mg.line([text])

- mg.link(<uri>, [text])

- mg.head(<text>, [level])

- mg.quote(<text>)

- mg.block(<text>)

- mg.begin_block([alt-text])

- mg.end_block()

### Header

- mg.set_language(<language>)

- mg.temp_redirect(<url>)

- mg.redirect(<url>)

- mg.temp_failure([meta])

- mg.unavailable([meta])

- mg.cgi_error([meta])

- mg.proxy_error([meta])

- mg.slow_down([meta])

- mg.failure([meta])

- mg.not_found([meta])

- mg.gone([meta])

- mg.proxy_refused([meta])

- mg.bad_request([meta])

- mg.cert_required([meta])

- mg.unauthorized([meta])

### Input

- mg.get_input([meta])

- mg.get_sensitive_input([meta])

- mg.has_input()

### Certificate

- mg.get_cert([meta])

- mg.has_cert()

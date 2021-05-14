[![builds.sr.ht status](https://builds.sr.ht/~panda-roux/MoonGem.svg)](https://builds.sr.ht/~panda-roux/MoonGem?)

# MoonGem

## Introduction

MoonGem is a Gemini protocol server written in C. It supports serving static files as well as Gemtext (.gmi) files with inline Lua scripting.

Inline scripts are indicated by special begin/end line tokens. An example page might look like this:

```lua
# Fibonacci Sequence 

-<<
function write_fibonacci(n)
 local i, j = 0, 1
  for k = 1, n do
    i, j = j, i + j

    -- write the result in a Gemtext bullet list
    BODY:line(string.format('* %d', i))
  end
end
>>-

Here are the first 20 members of the Fibonacci sequence:

-<<
write_fibonacci(20)
>>-
```

## Usage

```
./moongem <path-to-certificate.pem> <path-to-key.pem> <root-content-dir>
```

Optionally, set the MOONGEM_PORT environment variable to listen on a non-default network port.

## API

The start and end of script sections are indicated with a special sequence of characters, which must appear on their own lines, without any prefix:
* Start: `-<<`
* End: `>>-`

I chose these tokens because in my opinion they're visually distinctive and unlikely to be included in any typical content.

A single global variable PATH contains the path of the requested page (i.e. /my/document.gmi).

MoonGem exposes the following Lua functions for generating content:

`BODY:include(<path>)`
Inserts the contents of the file at <path>. Note that this DOES NOT run embedded scripts in the source document if a Gemtext file is specified. This is an intentional choice for the sake of simplicity.

`BODY:write(<text>)`
Writes <text> to the body of the document. No new-line character is appended.

`BODY:line(<text>)`
Writes <text> to the body of the document, followed by a new-line character.

`BODY:link(<url>, [text])`
Writes a link pointing to <url> to the body of the document. Optionally, [text] can be specified in order to append link alt-text.

`BODY:heading(<text>, <level>)`
Writes <text> as a heading line to the body of the document. The value of <level> indicates the heading level (in other words, <level> == number of #'s).

`BODY:block(<text>)`
Writes <text> in a preformatted block.

`BODY:begin_block([alt-text])`
Writes the beginning of a preformatted block with optional [alt-text].

`BODY:end_block()`
Writes the end of a preformatted block.

`HEAD:set_lang(<language>)`
Sets the language tag in the response header.

`HEAD:get_input([prompt]), HEAD:get_sensitive_input([prompt])`
Prompts the client for input and returns the result.

`HEAD:has_cert()`
Returns `true` if the client provided a certificate on this request; otherwise, `false`.

`HEAD:get_cert()`
Returns a table with the following structure fields (or nil if no cert is present):
- `fingerprint`: a string representation of a SHA256 hash of the client certificate's public key
- `not_after`: the certificate's expiration time, in seconds since the UNIX epoch


## Source

[The source code can be found here](https://git.sr.ht/~panda-roux/MoonGem/)

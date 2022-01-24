#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>
#include <stdio.h>

#include "gemini.h"

typedef struct evbuffer evbuffer;  // defined in libevent2

typedef struct script_ctx_t script_ctx_t;
typedef struct file_info_t file_info_t;

typedef struct parser_t {
  file_info_t* file;
  script_ctx_t* script_ctx;
  gemini_context_t* gemini;
} parser_t;

int init_parser_regex(void);

void cleanup_parser_regex(void);

parser_t* create_doc_parser(gemini_context_t* gemini, file_info_t* file,
                            script_ctx_t* script_ctx);

void parse_gemtext_doc(parser_t* parser, struct evbuffer* buffer);

void destroy_doc_parser(parser_t* parser);

#endif

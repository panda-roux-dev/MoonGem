#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>
#include <stdio.h>

typedef struct request_t request_t;
typedef struct response_t response_t;
typedef struct script_ctx_t script_ctx_t;
typedef struct evbuffer evbuffer;

typedef struct parser_t {
  script_ctx_t* script_ctx;
  const request_t* request;
  response_t* response;
  FILE* file;
} parser_t;

int init_parser_regex(void);

void cleanup_parser_regex(void);

parser_t* create_doc_parser(const struct request_t* request,
                            struct response_t* response, FILE* file);

void parse_gemtext_doc(parser_t* parser, struct evbuffer* buffer);

void destroy_doc_parser(parser_t* parser);

#endif

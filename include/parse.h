#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>
#include <stdio.h>

#include "net.h"

struct doc_state_t;

typedef struct {
  size_t written;
  struct doc_state_t* doc_state;
  const request_t* request;
  response_t* response;
  FILE* file;
  bool processed;
} parser_t;

parser_t* create_doc_parser(const request_t* request, response_t* response,
                            FILE* file);

void destroy_doc_parser(parser_t* parser);

size_t response_body_parser_cb(size_t max, char* buffer, void* data);

void response_parser_cleanup_cb(void* data);

#endif

#ifndef GEMINI_H
#define GEMINI_H

#include <stddef.h>

#include "net.h"
#include "options.h"
#include "uri.h"
#include "util.h"

typedef struct client_cert_t client_cert_t;

typedef struct request_t {
  client_cert_t* cert;
  uri_t* uri;
} request_t;

typedef struct response_t {
  int status;
  char* meta;
  char* mimetype;
  char* language;
  bool interrupted;
} response_t;

void listen_for_gemini_requests(cli_options_t* options);

#endif

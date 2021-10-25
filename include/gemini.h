#ifndef GEMINI_H
#define GEMINI_H

#include <stddef.h>

#include "log.h"
#include "net.h"
#include "options.h"
#include "uri.h"
#include "util.h"

#define RESPONSE_META_SIZE 128
#define RESPONSE_MIMETYPE_SIZE 32
#define RESPONSE_LANGUAGE_SIZE 32

#define RESPONSE_SET(buf, val)                                    \
  {                                                               \
    if (val != NULL) {                                            \
      LOG_DEBUG("Setting " #buf " to \"%s\"", val);               \
      snprintf(&(buf)[0], sizeof(buf) / sizeof(char), "%s", val); \
    } else {                                                      \
      LOG_DEBUG("Clearing " #buf);                                \
      buf[0] = '\0';                                              \
    }                                                             \
  }

#define set_response_meta(resp, val) RESPONSE_SET((resp)->meta, val)
#define set_response_lang(resp, val) RESPONSE_SET((resp)->language, val)
#define set_response_mime(resp, val) RESPONSE_SET((resp)->mimetype, val)

#define response_has_meta(resp) ((resp)->meta[0] != '\0')
#define response_has_lang(resp) ((resp)->language[0] != '\0')
#define response_has_mime(resp) ((resp)->mimetype[0] != '\0')

typedef struct client_cert_t client_cert_t;

typedef struct request_t {
  client_cert_t* cert;
  uri_t* uri;
} request_t;

typedef struct response_t {
  int status;
  char meta[RESPONSE_META_SIZE];
  char mimetype[RESPONSE_MIMETYPE_SIZE];
  char language[RESPONSE_LANGUAGE_SIZE];
  bool interrupted;
} response_t;

typedef struct gemini_state_t {
  request_t request;
  response_t response;
} gemini_state_t;

void listen_for_gemini_requests(cli_options_t* options);

void set_response_status(response_t* response, int code, const char* meta);

#endif

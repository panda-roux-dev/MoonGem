#ifndef NET_H
#define NET_H

#include <stddef.h>

typedef struct ssl_ctx_st _SSL_CTX;

typedef enum { OK, REDIRECT, ERROR } callback_result_t;

typedef struct {
  size_t path_length;
  const char* path;
} request_t;

typedef struct {
  size_t body_length;
  int status;
  char* body;
  char* meta;
  char* mimetype;
  char* language;
} response_t;

typedef callback_result_t (*request_callback_t)(const request_t*, response_t*);

typedef struct {
  int socket;
  _SSL_CTX* ssl_ctx;
} net_t;

net_t* init_socket(int port, const char* cert_path, const char* key_path);

void destroy_socket(net_t* net);

void handle_requests(net_t* net, request_callback_t callback);

#endif

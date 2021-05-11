#ifndef NET_H
#define NET_H

#include <stddef.h>

typedef struct ssl_ctx_st SSL_CTX;

typedef enum { OK, REDIRECT, ERROR } callback_result_t;

typedef struct {
  size_t path_length;
  const char* path;
} request_t;

/*
 * Returns actual number of bytes to the char buffer (<= than arg 1)
 */
typedef size_t (*response_body_callback_t)(size_t, char*, void*);

typedef void (*response_cleanup_callback_t)(void*);

typedef struct {
  void* data;
  response_body_callback_t build_body;
  response_cleanup_callback_t cleanup;
} response_body_builder_t;

typedef struct {
  int status;
  char* meta;
  char* mimetype;
  char* language;
} response_t;

typedef callback_result_t (*request_callback_t)(const request_t*, response_t*,
                                                response_body_builder_t*);

void init_body_builder(response_body_builder_t* builder,
                       response_body_callback_t body_cb,
                       response_cleanup_callback_t cleanup, void* data);

typedef struct {
  int socket;
  SSL_CTX* ssl_ctx;
} net_t;

void set_response_body_callback(response_t* response,
                                response_body_callback_t* cb, void* data);

net_t* init_socket(int port, const char* cert_path, const char* key_path);

void destroy_socket(net_t* net);

void handle_requests(net_t* net, request_callback_t callback);

#endif

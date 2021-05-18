#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct client_cert_t client_cert_t;

typedef enum callback_result_t { OK, ERROR } callback_result_t;

typedef struct request_t {
  size_t path_length;
  client_cert_t* cert;
  const char* path;
  const char* input;
} request_t;

/*
 * The callback function used for buffering chunks of a response body;
 * receives the following arguments:
 * - The maximum number of bytes that may be copied into the buffer
 * - The buffer itself
 * - A pointer to implementation-defined data
 *
 * Returns actual number of bytes to the char buffer (<= than arg1)
 */
typedef size_t (*response_body_callback_t)(size_t, char*, void*);

/*
 * Called after the full body of the response has been sent to the client;
 * cleans up any resources allocated by the body implementation
 */
typedef void (*response_cleanup_callback_t)(void*);

/*
 * Convenience object for containing response body build + cleanup callbacks,
 * and the opaque pointer to the data used by the builder implementation
 */
typedef struct response_body_builder_t {
  void* data;
  response_body_callback_t build_body;
  response_cleanup_callback_t cleanup;
} response_body_builder_t;

typedef struct response_t {
  int status;
  char* meta;
  char* mimetype;
  char* language;
  bool interrupted;
} response_t;

/*
 * Called once in order to begin the process of building a response.
 *
 * The implementation should call init_body_builder(...) and assign the result
 * to the third argument.
 */
typedef callback_result_t (*request_callback_t)(const request_t*, response_t*,
                                                response_body_builder_t*);

void init_body_builder(response_body_builder_t* builder,
                       response_body_callback_t body_cb,
                       response_cleanup_callback_t cleanup, void* data);

typedef struct net_t {
  int socket;
  SSL_CTX* ssl_ctx;
} net_t;

void set_response_status(response_t* response, int status, const char* msg);

void set_response_body_callback(response_t* response,
                                response_body_callback_t* cb, void* data);

net_t* init_socket(int port, const char* cert_path, const char* key_path);

void destroy_socket(net_t* net);

void handle_requests(net_t* net, request_callback_t callback);

#endif


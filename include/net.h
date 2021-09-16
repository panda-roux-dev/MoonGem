#ifndef NET_H
#define NET_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct client_cert_t client_cert_t;

typedef struct net_t {
  int socket;
  SSL_CTX* ssl_ctx;
} net_t;
net_t* init_tls_socket(int port, const char* cert_path, const char* key_path);

net_t* init_socket(int port);

void destroy_socket(net_t* net);

void log_remote_address(int sock);

#endif


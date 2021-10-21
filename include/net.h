#ifndef NET_H
#define NET_H

#include "options.h"

typedef struct ssl_ctx_st SSL_CTX;

typedef struct net_t {
  struct sockaddr* addr;
  SSL_CTX* ssl_ctx;
  int addr_size;
} net_t;

net_t* init_net(const cli_options_t* options);

void destroy_net(net_t* net);

void log_remote_address(int sock);

#endif


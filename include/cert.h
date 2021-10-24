#ifndef CERT_H
#define CERT_H

#include <stdbool.h>

#define CLIENT_CERT_INDEX 0

typedef struct x509_store_ctx_st X509_STORE_CTX;

typedef struct client_cert_t {
  char* fingerprint;
  unsigned long not_after;
  bool initialized;
} client_cert_t;

void destroy_client_cert(client_cert_t* cert);

int handle_client_certificate(int preverify_ok, X509_STORE_CTX* ctx);

#endif

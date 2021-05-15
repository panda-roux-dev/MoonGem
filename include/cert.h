#ifndef CERT_H
#define CERT_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
  char* fingerprint;
  unsigned long not_after;
  bool initialized;
} client_cert_t;

typedef struct x509_st X509;
typedef struct x509_store_ctx_st X509_STORE_CTX;

int get_client_cert_index(void);

void destroy_client_cert(client_cert_t* cert);

unsigned char* get_modulus_from_x509(X509* certificate, size_t* len);

unsigned int get_x509_expiration(X509* certificate);

int handle_client_certificate(int preverify_ok, X509_STORE_CTX* ctx);

#endif

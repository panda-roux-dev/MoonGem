#include "net.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "cert.h"
#include "log.h"

#define SET_CERTS_FAILURE INT_MIN

static struct sockaddr* create_addr(int port, int* addr_size) {
  struct sockaddr_in6* addr = calloc(1, sizeof(struct sockaddr_in6));
  addr->sin6_family = AF_INET6;
  addr->sin6_port = htons(port);
  addr->sin6_addr = in6addr_any;

  *addr_size = sizeof(struct sockaddr_in6);

  return (struct sockaddr*)addr;
}

static SSL_CTX* init_ssl_context(void) {
  const SSL_METHOD* method = TLS_server_method();

  SSL_CTX* ctx;
  if ((ctx = SSL_CTX_new(method)) == NULL) {
    LOG_ERROR("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                     handle_client_certificate);
  SSL_CTX_set_verify_depth(ctx, 0);
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options(
      ctx, SSL_OP_NO_TICKET | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  return ctx;
}

static int set_certs(SSL_CTX* ctx, const char* cert_path,
                     const char* key_path) {
  SSL_CTX_set_ecdh_auto(ctx, 1);

  LOG("Using certificate file from %s", cert_path);
  if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return SET_CERTS_FAILURE;
  }

  LOG("Using private key file from %s", key_path);
  if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    return SET_CERTS_FAILURE;
  }

  return 0;
}

static void cleanup_ssl(SSL_CTX* ctx) {
  if (ctx != NULL) {
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL, CLIENT_CERT_INDEX);
    SSL_CTX_free(ctx);
  }

  // FIPS_mode_set(0);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  EVP_cleanup();
}

net_t* init_net(const cli_options_t* options) {
  SSL_CTX* ctx;
  if ((ctx = init_ssl_context()) == NULL) {
    return NULL;
  }

  if (set_certs(ctx, options->cert_path, options->key_path) ==
      SET_CERTS_FAILURE) {
    cleanup_ssl(ctx);
    return NULL;
  }

  net_t* net = calloc(1, sizeof(net_t));
  net->ssl_ctx = ctx;
  net->addr = create_addr(options->gemini_port, &net->addr_size);

  return net;
}

void destroy_net(net_t* net) {
  if (net == NULL) {
    return;
  }

  if (net->addr != NULL) {
    free(net->addr);
  }

  if (net->ssl_ctx != NULL) {
    cleanup_ssl(net->ssl_ctx);
  }

  free(net);
}

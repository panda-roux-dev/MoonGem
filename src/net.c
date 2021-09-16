#include "net.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cert.h"
#include "log.h"

#define CREATE_SOCKET_FAILURE INT_MIN
#define SET_CERTS_FAILURE INT_MIN

static const int OPT_OFF = 0;
static const int OPT_ON = 1;

static int create_socket(int port) {
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
  addr.sin6_addr = in6addr_any;

  int sock = socket(AF_INET6, SOCK_STREAM, 0);

  // accept either IPv4 or IPv6
  setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &OPT_OFF, sizeof(OPT_OFF));
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &OPT_ON, sizeof(OPT_ON));

  if (sock < 0) {
    LOG_ERROR("Failed to create an IPv4 socket");
    return CREATE_SOCKET_FAILURE;
  }

  if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("Failed to bind IPv4 socket");
    return CREATE_SOCKET_FAILURE;
  }

  if (listen(sock, 1) < 0) {
    LOG_ERROR("Failed to listen on IPv4 socket");
    return CREATE_SOCKET_FAILURE;
  }

  return sock;
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
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL, get_client_cert_index());
    SSL_CTX_free(ctx);
  }

  FIPS_mode_set(0);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  EVP_cleanup();
}

void log_remote_address(int sock) {
  int port;
  struct sockaddr_storage addr_storage;
  char addr_str[INET6_ADDRSTRLEN];
  socklen_t len = sizeof(addr_str);
  getpeername(sock, (struct sockaddr*)&addr_storage, &len);
  switch (addr_storage.ss_family) {
    case AF_INET: {
      struct sockaddr_in* addr = (struct sockaddr_in*)&addr_storage;
      port = ntohs(addr->sin_port);
      inet_ntop(AF_INET, &addr->sin_addr, addr_str, sizeof(addr_str));
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6* addr = (struct sockaddr_in6*)&addr_storage;
      port = ntohs(addr->sin6_port);
      inet_ntop(AF_INET6, &addr->sin6_addr, addr_str, sizeof(addr_str));
      break;
    }
    default:
      LOG("Unknown socket family %d", addr_storage.ss_family);
      return;
  }

  LOG_NOLF("[%s:%d]", addr_str, port);
}

net_t* init_socket(int port) {
  int sock;
  if ((sock = create_socket(port)) == CREATE_SOCKET_FAILURE) {
    return NULL;
  }

  net_t* net = malloc(sizeof(net_t));
  net->socket = sock;
  net->ssl_ctx = NULL;

  return net;
}

net_t* init_tls_socket(int port, const char* cert_path, const char* key_path) {
  SSL_CTX* ctx;
  if ((ctx = init_ssl_context()) == NULL) {
    return NULL;
  }

  if (set_certs(ctx, cert_path, key_path) == SET_CERTS_FAILURE) {
    cleanup_ssl(ctx);
    return NULL;
  }

  int sock;
  if ((sock = create_socket(port)) == CREATE_SOCKET_FAILURE) {
    cleanup_ssl(ctx);
    return NULL;
  }

  net_t* net = malloc(sizeof(net_t));
  net->socket = sock;
  net->ssl_ctx = ctx;

  return net;
}

void destroy_socket(net_t* net) {
  if (net == NULL) {
    return;
  }

  close(net->socket);

  if (net->ssl_ctx != NULL) {
    cleanup_ssl(net->ssl_ctx);
  }

  free(net);
}


#include "net.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include "hashdef.h"
#include "header.h"
#include "log.h"
#include "status.h"

#define CREATE_SOCKET_FAILURE INT_MIN
#define SET_CERTS_FAILURE INT_MIN

#define RESPONSE_BODY_BUFFER_LENGTH 4096

#define ERROR_MSG "Server error"

DEFINE_SHA_OFSIZE(256)

static volatile sig_atomic_t terminate = 0;
static volatile sig_atomic_t stop = 0;

static int client_cert_index = 0;

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

static void destroy_client_cert(client_cert_t* cert) {
  if (cert != NULL) {
    if (cert->fingerprint != NULL) {
      free(cert->fingerprint);
    }

    free(cert);
  }
}

static unsigned char* get_modulus_from_x509(X509* certificate, size_t* len) {
  EVP_PKEY* key = X509_get_pubkey(certificate);

  struct rsa_st* rsa = EVP_PKEY_get1_RSA(key);
  const BIGNUM* modulus = RSA_get0_n(rsa);

  // store key contents in a buffer
  *len = BN_num_bytes(modulus);
  unsigned char* buffer = malloc(sizeof(unsigned char) * (*len));
  BN_bn2bin(modulus, buffer);

  RSA_free(rsa);
  EVP_PKEY_free(key);

  return buffer;
}

static unsigned int get_x509_expiration(X509* certificate) {
  ASN1_TIME* notafter = X509_get_notAfter(certificate);
  ASN1_TIME* epoch = ASN1_TIME_new();
  ASN1_TIME_set_string(epoch, "700101000000Z");

  int days, seconds;
  ASN1_TIME_diff(&days, &seconds, epoch, notafter);

  ASN1_TIME_free(epoch);

  return (days * 24 * 60 * 60) + seconds;
}

static int handle_client_certificate(int preverify_ok, X509_STORE_CTX* ctx) {
  SSL* ssl =
      X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

  X509* x509 = X509_STORE_CTX_get0_cert(ctx);
  client_cert_t* cert = (client_cert_t*)SSL_get_ex_data(ssl, client_cert_index);

  if (cert != NULL && !cert->initialized) {
    LOG_DEBUG("Reading the provided client certificate...");

    // set this flag so that we don't perform this logic multiple times (leading
    // to memory leaks when re-allocating the fingerprint needlessly)
    //
    // i tried to work around this with SSL_VERIFY_CLIENT_ONCE and depth=0, but
    // apparently OpenSSL has other plans and it isn't telling me what they are;
    // so we have to do this
    cert->initialized = true;

    size_t pubkey_len = 0;
    hash_buffer_256_t hash;
    unsigned char* modulus = get_modulus_from_x509(x509, &pubkey_len);
    size_t hash_len = compute_sha256_hash(&hash, modulus, pubkey_len);
    free(modulus);

    // allocate space for each hash byte to be illustrated as 2 characters, plus
    // a null terminator
    const size_t fingerprint_len = hash_len * 2;
    cert->fingerprint = malloc((fingerprint_len + 1) * sizeof(char));
    if (cert->fingerprint == NULL) {
      LOG_ERROR("Failed to allocate space for certificate fingerprint");
      return 0;
    }

    for (int i = 0; i < hash_len; ++i) {
      snprintf(&cert->fingerprint[i], 2, "%02x", hash.data[i]);
    }

    cert->fingerprint[fingerprint_len] = '\0';
    cert->not_after = get_x509_expiration(x509);
  } else {
    LOG_DEBUG(
        "Client certificate was already read for this request; skipping...");
  }

  return 1;
}

static void init_openssl(void) {}

SSL_CTX* init_ssl_context(void) {
  const SSL_METHOD* method = TLS_server_method();

  SSL_CTX* ctx;
  if ((ctx = SSL_CTX_new(method)) == NULL) {
    LOG_ERROR("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                     handle_client_certificate);
  SSL_CTX_set_verify_depth(ctx, 0);

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
    CRYPTO_free_ex_index(CRYPTO_EX_INDEX_SSL, client_cert_index);
    SSL_CTX_free(ctx);
  }

  FIPS_mode_set(0);
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();
  EVP_cleanup();
}

static void sig_terminate_handler(int sig) {
  LOG_DEBUG("Received signal %d; terminating...", sig);
  terminate = 1;
}

static void sig_stop_handler(int sig) {
  LOG_DEBUG("Received SIGSTOP;  stopping...");
  stop = 1;
}

static void sig_kill_handler(int _) { exit(EXIT_FAILURE); }

static void set_signal_handler(net_t* net) {
  signal(SIGKILL, sig_kill_handler);
  signal(SIGTERM, sig_terminate_handler);
  signal(SIGABRT, sig_terminate_handler);
  signal(SIGINT, sig_terminate_handler);
  signal(SIGSTOP, sig_stop_handler);
  signal(SIGTSTP, sig_stop_handler);
}

static void wait_until_continue(void) {
  LOG_DEBUG("Stopped.  Waiting for another signal...");

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGABRT);
  sigaddset(&set, SIGINT);

  int sig;
  sigwait(&set, &sig);

  LOG_DEBUG("Received signal %d.  Continuing...", sig);

  stop = 0;
  if (sig != SIGCONT) {
    if (sig != SIGKILL) {
      terminate = 1;
    } else {
      exit(EXIT_FAILURE);
    }
  }
}

net_t* init_socket(int port, const char* cert_path, const char* key_path) {
  LOG_DEBUG("Initializing network resources...");

  init_openssl();

  SSL_CTX* ctx;
  if ((ctx = init_ssl_context()) == NULL) {
    return NULL;
  }

  if (set_certs(ctx, cert_path, key_path) == SET_CERTS_FAILURE) {
    cleanup_ssl(ctx);
    return NULL;
  }

  LOG_DEBUG("Loaded certificate and key");

  int sock;
  if ((sock = create_socket(port)) == CREATE_SOCKET_FAILURE) {
    cleanup_ssl(ctx);
    return NULL;
  }

  LOG_DEBUG("Created socket (%d)", sock);

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
  cleanup_ssl(net->ssl_ctx);

  free(net);

  LOG_DEBUG("Network resources destroyed");
}

static void send_status_response(SSL* ssl, int code, const char* meta) {
  LOG_DEBUG("Sending response with status %d", code);

  size_t len;
  char* header = build_response_header(code, (char*)meta, &len);
  if (header != NULL) {
    SSL_write(ssl, header, len);
    free(header);
  }
}

void set_response_status(response_t* response, int status, const char* msg) {
  response->status = status;
  response->meta = strdup(msg);
}

static void free_response_fields(response_t* response) {
  if (response->meta != NULL) {
    free(response->meta);
  }

  if (response->mimetype != NULL) {
    free(response->mimetype);
  }

  if (response->language != NULL) {
    free(response->language);
  }
}

static void handle_success_response(SSL* ssl, response_t* response,
                                    response_body_builder_t* builder) {
  if (builder != NULL && builder->build_body != NULL) {
    char buffer[RESPONSE_BODY_BUFFER_LENGTH];
    response_body_callback_t build_func = builder->build_body;

    // run the body builder function once; this gives any scripts a chance to
    // interrupt the response before a success header is sent.
    //
    // after this point, it can be assumed that all scripts have been run and
    // that response->interrupted will be set if need be.  otherwise serve the
    // rest of the body
    size_t current_length =
        build_func(sizeof(buffer) / sizeof(char), &buffer[0], builder->data);

    if (!response->interrupted && current_length > 0) {
      // no interruptions and we got data; send the header and first chunk of
      // the body

      // generate a SUCCESS response header
      size_t header_length = 0;
      char* tags = build_tags(response);
      char* header =
          build_response_header(STATUS_SUCCESS, tags, &header_length);

      free(tags);

      if (header == NULL) {
        LOG_ERROR("Failed to allocate memory for the response header");
        send_status_response(ssl, STATUS_TEMPORARY_FAILURE, ERROR_MSG);
        return;
      }

      SSL_write(ssl, header, header_length);
      SSL_write(ssl, &buffer[0], current_length);

      // send the rest of the body
      for (;;) {
        if (response->interrupted ||
            (current_length = build_func(sizeof(buffer) / sizeof(char),
                                         &buffer[0], builder->data)) == 0) {
          // finished
          break;
        }

        LOG_DEBUG("Sending %zu bytes to the client", current_length);
        SSL_write(ssl, &buffer[0], current_length);
      }

      free(header);
    } else if (response->interrupted) {
      // something in a script decided to end the response prematurely;
      // send a status header accordingly

      LOG_DEBUG("Response interrupted");
      send_status_response(ssl, response->status, response->meta);
    }
  }

  response_cleanup_callback_t cleanup = builder->cleanup;
  if (cleanup != NULL) {
    cleanup(builder->data);
  }
}

static void handle_error_response(SSL* ssl, response_t* response) {
  if (response->status == 0) {
    LOG_DEBUG("No error status code provided;  defaulting to %d",
              STATUS_TEMPORARY_FAILURE);
    response->status = STATUS_TEMPORARY_FAILURE;
  }

  if (response->meta == NULL) {
    const char msg[] = "Server error";
    response->meta = strndup(&msg[0], sizeof(msg) / sizeof(char));
  }

  send_status_response(ssl, response->status, response->meta);
}

static void send_body_response(SSL* ssl, size_t path_length,
                               const char* const path,
                               request_callback_t callback,
                               const char* const input) {
  client_cert_t* cert = (client_cert_t*)SSL_get_ex_data(ssl, client_cert_index);
  if (cert != NULL && cert->fingerprint != NULL) {
    LOG_DEBUG("Client cert fingerprint: %s", cert->fingerprint);
  }

  request_t request = {path_length, cert, path, input};
  response_t response = {0, NULL, NULL, NULL, false};

  response_body_builder_t builder;
  switch (callback(&request, &response, &builder)) {
    case OK:
      LOG_DEBUG("Sending SUCCESS response");
      handle_success_response(ssl, &response, &builder);
      break;
    case ERROR:
      LOG_DEBUG("Sending ERROR response");
      handle_error_response(ssl, &response);
      break;
    default:
      LOG_ERROR("Unknown callback result");
      send_status_response(ssl, STATUS_TEMPORARY_FAILURE,
                           "Unknown server error");
      break;
  }

  destroy_client_cert(cert);
  free_response_fields(&response);
}

void init_body_builder(response_body_builder_t* builder,
                       response_body_callback_t body_cb,
                       response_cleanup_callback_t cleanup, void* data) {
  builder->build_body = body_cb;
  builder->cleanup = cleanup;
  builder->data = data;
}

static client_cert_t* create_client_cert() {
  client_cert_t* cert = malloc(sizeof(client_cert_t));
  if (cert == NULL) {
    LOG_ERROR("Failed to allocate memory for client cert object");
  }

  cert->fingerprint = NULL;
  cert->not_after = 0;
  cert->initialized = false;

  return cert;
}

void handle_requests(net_t* net, request_callback_t callback) {
  char request_buffer[MAX_URL_LENGTH + 2];  // + 2 for CR + LF

  LOG_DEBUG("Request buffer is %zu bytes in length",

            sizeof(request_buffer) / sizeof(char));

  LOG_DEBUG("Listening for requests...");

  while (!terminate) {
    if (stop) {
      wait_until_continue();
    }

    int client;
    if ((client = accept(net->socket, NULL, NULL)) < 0) {
      LOG_ERROR("Failed to accept connection");
      return;
    }

    SSL* ssl = SSL_new(net->ssl_ctx);
    SSL_set_fd(ssl, client);
    SSL_set_ex_data(ssl, client_cert_index, create_client_cert());

    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
    } else {
      LOG_DEBUG("Request received");

      memset(&request_buffer[0], '\0', sizeof(request_buffer) / sizeof(char));
      SSL_read(ssl, &request_buffer[0], sizeof(request_buffer) / sizeof(char));

      size_t path_length;
      char* path = malloc(sizeof(char) * MAX_URL_LENGTH);
      if (path == NULL) {
        LOG_ERROR(
            "Failed to allocate enough memory for the incoming request path");
        send_status_response(ssl, STATUS_TEMPORARY_FAILURE, ERROR_MSG);
      } else {
        if (extract_path(&request_buffer[0], path, &path_length) != 0) {
          LOG_DEBUG(
              "Client sent an invalid request.  No path could be inferred.");

          send_status_response(ssl, STATUS_BAD_REQUEST, "Invalid URL");
        } else {
          LOG_DEBUG("Requested path: %s", path);

          char* input = extract_input(&request_buffer[0]);
          if (input != NULL) {
            LOG_DEBUG("Received input: %s", input);
          }

          send_body_response(ssl, path_length, path, callback, input);

          if (input != NULL) {
            free(input);
          }
        }

        free(path);
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
  }
}

#include "net.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cert.h"
#include "hashdef.h"
#include "header.h"
#include "http.h"
#include "log.h"
#include "status.h"
#include "util.h"

#define CREATE_SOCKET_FAILURE INT_MIN
#define SET_CERTS_FAILURE INT_MIN

#define HTTP_REQUEST_BUFFER_LENGTH 8192
#define HTTP_MAX_REQUEST_LENGTH (HTTP_REQUEST_BUFFER_LENGTH * 1000)
#define RESPONSE_BODY_BUFFER_LENGTH 4096
#define ERROR_MSG "Server error"

static volatile sig_atomic_t terminate = 0;
static volatile sig_atomic_t stop = 0;

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

static void sig_terminate_handler(int sig) { terminate = 1; }

static void sig_stop_handler(int sig) { stop = 1; }

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
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGABRT);
  sigaddset(&set, SIGINT);

  int sig;
  sigwait(&set, &sig);

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
  cleanup_ssl(net->ssl_ctx);

  free(net);
}

static void send_status_response(SSL* ssl, int code, const char* meta) {
  size_t len;
  char* header = build_response_header(code, (char*)meta, &len);
  if (header != NULL) {
    LOG(" | %d %s", code, meta);
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

      size_t total_size = 0;

      SSL_write(ssl, header, header_length);

      SSL_write(ssl, &buffer[0], current_length);
      total_size += current_length;

      // send the rest of the body
      for (;;) {
        if (response->interrupted ||
            (current_length = build_func(sizeof(buffer) / sizeof(char),
                                         &buffer[0], builder->data)) == 0) {
          // finished
          break;
        }

        SSL_write(ssl, &buffer[0], current_length);
        total_size += current_length;
      }

      LOG(" | %zu header + %zu body bytes sent (total: %zu)", header_length,
          total_size, total_size + header_length);

      free(header);
    } else if (response->interrupted) {
      // something in a script decided to end the response prematurely;
      // send a status header accordingly

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
    response->status = STATUS_TEMPORARY_FAILURE;
  }

  if (response->meta == NULL) {
    const char msg[] = "Server error";
    response->meta = strndup(&msg[0], sizeof(msg) / sizeof(char));
  }

  send_status_response(ssl, response->status, response->meta);
}

static void send_body_response(SSL* ssl, size_t path_length, const char* path,
                               request_callback_t callback, const char* input) {
  client_cert_t* cert =
      (client_cert_t*)SSL_get_ex_data(ssl, get_client_cert_index());

  request_t request = {path_length, cert, path, input};
  response_t response = {0, NULL, NULL, NULL, false};

  response_body_builder_t builder;
  switch (callback(&request, &response, &builder)) {
    case OK:
      handle_success_response(ssl, &response, &builder);
      break;
    case ERROR:
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
    return NULL;
  }

  cert->fingerprint = NULL;
  cert->not_after = 0;
  cert->initialized = false;

  return cert;
}

static void log_remote_info(int sock) {
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

void handle_http_requests(net_t* net, request_callback_t callback) {
  while (!terminate) {
    if (stop) {
      wait_until_continue();
    }

    int client;
    if ((client = accept(net->socket, NULL, NULL)) < 0) {
      LOG_ERROR("Failed to accept connection");
      return;
    }

    log_remote_info(client);

    text_buffer_t* request_body = create_buffer();

    char read_buffer[HTTP_REQUEST_BUFFER_LENGTH];
    int read_length = 0;
    while ((read_length =
                read(client, read_buffer, HTTP_REQUEST_BUFFER_LENGTH)) > 0) {
      buffer_append(request_body, read_buffer, read_length);
      if (request_body->length >= HTTP_MAX_REQUEST_LENGTH) {
        LOG_ERROR(
            "Terminating the request early as maximum request size of %d "
            "bytes has been reached",
            HTTP_MAX_REQUEST_LENGTH);

        // TODO: return error "413: Payload Too Large"
        write_status_code_response(client, 413, "Payload Too Large");
        break;
      }
    }

    write_status_code_response(client, 200, "OK");

    clear_buffer(request_body);

    close(client);
  }
}

void handle_gemini_requests(net_t* net, request_callback_t callback) {
  while (!terminate) {
    if (stop) {
      wait_until_continue();
    }

    int client;
    if ((client = accept(net->socket, NULL, NULL)) < 0) {
      LOG_ERROR("Failed to accept connection");
      return;
    }

    log_remote_info(client);

    SSL* ssl = SSL_new(net->ssl_ctx);
    SSL_set_fd(ssl, client);
    SSL_set_ex_data(ssl, get_client_cert_index(), create_client_cert());

    if (SSL_accept(ssl) <= 0) {
      ERR_print_errors_fp(stderr);
    } else {
      char request_buffer[MAX_URL_LENGTH + 2];  // + 2 for CR + LF
      memset(&request_buffer[0], '\0', sizeof(request_buffer) / sizeof(char));
      SSL_read(ssl, &request_buffer[0], sizeof(request_buffer) / sizeof(char));

      size_t path_length;
      char path[MAX_URL_LENGTH];
      memset(&path[0], 0, sizeof(path) / sizeof(char));
      if (extract_path(&request_buffer[0], path, &path_length) != 0) {
        send_status_response(ssl, STATUS_BAD_REQUEST,
                             strndup(&request_buffer[0], path_length));
      } else {
        char input[MAX_URL_LENGTH];
        memset(&input[0], 0, sizeof(input) / sizeof(char));
        size_t input_len = extract_input(&request_buffer[0], &input[0]);

        if (input_len == 0) {
          LOG_NOLF(" %s", path);
          send_body_response(ssl, path_length, path, callback, NULL);
        } else {
          LOG_NOLF(" %s?%s", path, input);
          send_body_response(ssl, path_length, path, callback, input);
        }
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
  }
}

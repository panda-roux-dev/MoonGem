#include "net.h"

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "status.h"

#define CREATE_SOCKET_FAILURE INT_MIN
#define SET_CERTS_FAILURE INT_MIN
#define EXTRACT_PATH_FAILURE INT_MIN

#define MAX_URL_LENGTH 1024
#define MAX_META_LENGTH 1024
#define RESPONSE_BODY_BUFFER_LENGTH 4096
#define HEADER_BUFFER_LENGTH 1029  // code(2) + space(1) + meta(1024) + \r\n

#define ERROR_MSG "Server error"

#define URL_SCHEME "gemini://"
#define URL_TERMINATOR "\r\n"

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

static void init_openssl(void) {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

SSL_CTX* init_ssl_context(void) {
  const SSL_METHOD* method = TLS_server_method();

  SSL_CTX* ctx;
  if ((ctx = SSL_CTX_new(method)) == NULL) {
    LOG_ERROR("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

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
    SSL_CTX_free(ctx);
  }

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

static int extract_path(char* request, char* buffer, size_t* length) {
  // first check that the request body begins with the URL scheme
  if (strstr(request, URL_SCHEME) != request) {
    return EXTRACT_PATH_FAILURE;
  }

  // host starts after the scheme
  char* host_begin = &request[sizeof(URL_SCHEME) / sizeof(char)];

  // ensure that there's a \r\n terminating the request
  char* term = strstr(request, URL_TERMINATOR);
  if (term == NULL || term == host_begin) {
    return EXTRACT_PATH_FAILURE;
  }

  // path (if one exists) is everything between the first forward-slash after
  // the host and the \r\n terminator
  char* path = memchr(host_begin, '/', term - host_begin);

  // check if a path exists; if so, copy it into the buffer.
  //
  // otherwise, set length to zero and set up the buffer as an empty string
  size_t len;
  if (path != NULL) {
    len = term - path;
    memcpy(buffer, path, len);
    buffer[len] = '\0';
  } else {
    len = 0;
    buffer[0] = '\0';
  }

  *length = len;
  return 0;
}

static char* build_tags(response_t* response) {
  char* buffer = malloc(MAX_META_LENGTH * sizeof(char));
  memset(buffer, '\0', MAX_META_LENGTH);

  if (buffer == NULL) {
    LOG_ERROR("Failed to allocate response header tags buffer");
    return NULL;
  }

  int tags_written = 0;
  int offset = 0;
  if (response->meta != NULL) {
    offset += snprintf(buffer, MAX_META_LENGTH, "%s", response->meta);
    ++tags_written;
  }

  if (response->mimetype != NULL) {
    if (tags_written > 0) {
      offset += snprintf(buffer, MAX_META_LENGTH - offset, "; %s",
                         response->mimetype);
    } else {
      offset += snprintf(buffer, MAX_META_LENGTH, "%s", response->mimetype);
    }
    ++tags_written;
  }

  if (response->language != NULL) {
    if (tags_written > 0) {
      snprintf(buffer, MAX_META_LENGTH - offset, "; lang=%s",
               response->language);
    } else {
      snprintf(buffer, MAX_META_LENGTH, "lang=%s", response->language);
    }
  }

  return buffer;
}

static char* build_response_header(int status, char* meta, size_t* length) {
  // set up an initial buffer with enough space to store the header
  char header[HEADER_BUFFER_LENGTH];
  memset(&header[0], '\0', HEADER_BUFFER_LENGTH);

  // check size of the meta field, if it's set;
  //
  // - if meta is set, then validate its length and write it into the header
  // - otherwise if meta is not set, write a header without it
  size_t header_len = 0;
  if (meta != NULL) {
    header_len =
        snprintf(&header[0], HEADER_BUFFER_LENGTH, "%d %s\r\n", status, meta);
  } else {
    header_len = snprintf(&header[0], HEADER_BUFFER_LENGTH, "%d\r\n", status);
  }

  if (header_len >= HEADER_BUFFER_LENGTH || header_len <= 0) {
    LOG_ERROR("Failed to generate a response header");
    return NULL;
  }

  LOG_DEBUG("Generated a response header of length %zu", header_len);
  *length = header_len;

  // return a copy of the header in a heap-allocated buffer
  char* copy = strndup(&header[0], header_len);
  if (copy == NULL) {
    LOG_ERROR("Failed to allocate header buffer");
  }

  LOG_DEBUG("Response header: %s", header);

  return copy;
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
  // first generate a response header
  size_t header_length = 0;
  char* tags = build_tags(response);
  char* header = build_response_header(STATUS_SUCCESS, tags, &header_length);

  if (tags != NULL) {
    free(tags);
  }

  if (header == NULL) {
    LOG_ERROR("No response header allocated");
    return;
  }

  SSL_write(ssl, header, header_length);
  if (builder != NULL && builder->build_body != NULL) {
    size_t current_length = 0;
    char buffer[RESPONSE_BODY_BUFFER_LENGTH];
    response_body_callback_t build_func = builder->build_body;
    for (;;) {
      if ((current_length = build_func(sizeof(buffer) / sizeof(char),
                                       &buffer[0], builder->data)) == 0) {
        // finished
        break;
      }

      LOG_DEBUG("Sending %zu bytes to the client", current_length);

      SSL_write(ssl, &buffer[0], current_length);
    }
  }

  response_cleanup_callback_t cleanup = builder->cleanup;
  if (cleanup != NULL) {
    cleanup(builder->data);
  }
}

static void handle_redirect_response(SSL* ssl, response_t* response) {
  if (response->meta == NULL) {
    LOG_ERROR(
        "Attempted to send a redirect response without specifying a "
        "URL to redirect the client to!");
    send_status_response(ssl, STATUS_TEMPORARY_FAILURE,
                         "Error sending redirect response");
    return;
  }

  send_status_response(ssl, STATUS_TEMPORARY_REDIRECT, response->meta);
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
                               request_callback_t callback) {
  request_t request = {path_length, path};

  response_t response;
  memset(&response, 0, sizeof(response_t));

  response_body_builder_t builder;
  switch (callback(&request, &response, &builder)) {
    case OK:
      LOG_DEBUG("Sending SUCCESS response");
      handle_success_response(ssl, &response, &builder);
      break;
    case REDIRECT:
      LOG_DEBUG("Sending REDIRECT response");
      handle_redirect_response(ssl, &response);
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

  free_response_fields(&response);
}

void init_body_builder(response_body_builder_t* builder,
                       response_body_callback_t body_cb,
                       response_cleanup_callback_t cleanup, void* data) {
  builder->build_body = body_cb;
  builder->cleanup = cleanup;
  builder->data = data;
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
        if (extract_path(&request_buffer[0], path, &path_length) ==
            EXTRACT_PATH_FAILURE) {
          LOG_DEBUG(
              "Client sent an invalid request.  No path could be inferred.");
          send_status_response(ssl, STATUS_BAD_REQUEST, "Invalid URL");
        } else {
          LOG_DEBUG("Requested path: %s", path);
          send_body_response(ssl, path_length, path, callback);
        }

        free(path);
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
  }
}

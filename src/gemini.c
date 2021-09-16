#include "gemini.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cert.h"
#include "header.h"
#include "log.h"
#include "net.h"
#include "status.h"
#include "util.h"

#define RESPONSE_BODY_BUFFER_LENGTH 4096
#define ERROR_MSG "Server error"
#define DEFAULT_DOCUMENT "index.gmi"
#define EXT_GMI ".gmi"
#define INVALID_URL_PATTERNS "/..", "/.", "/../", "/./", "~/", "$"

static bool path_is_gmi(const char* path) {
  if (path == NULL) {
    return false;
  }

  return strcmp(strrchr(path, '.'), EXT_GMI) == 0;
}

static bool is_dir(const char* path) { return strrchr(path, '.') == NULL; }

static char* append_default_doc(const request_t* request) {
  size_t path_buf_len =
      (request->path_length) + sizeof(DEFAULT_DOCUMENT) / sizeof(char);
  char* path = malloc((path_buf_len + 1) * sizeof(char));
  if (path == NULL) {
    LOG_ERROR("Failed to append default document name to URL");
    return NULL;
  }

  memcpy(path, request->path, request->path_length * sizeof(char));
  if (request->path[request->path_length - 1] != '/') {
    path[request->path_length] = '/';
    memcpy(&path[request->path_length + 1], &DEFAULT_DOCUMENT[0],
           sizeof(DEFAULT_DOCUMENT));
  } else {
    memcpy(&path[request->path_length], &DEFAULT_DOCUMENT[0],
           sizeof(DEFAULT_DOCUMENT));
  }

  path[path_buf_len] = '\0';

  return path;
}

static bool path_is_illegal(const char* path) {
  const char* bad_strings[] = {INVALID_URL_PATTERNS};
  for (int i = 0; i < sizeof(bad_strings) / sizeof(char*); ++i) {
    if (strstr(path, bad_strings[i]) != NULL) {
      return true;
    }
  }

  return false;
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

void handle_gemini_requests(net_t* net, request_callback_t callback) {
  while (!should_terminate()) {
    if (is_stopped()) {
      wait_until_continue();
    }

    int client;
    if ((client = accept(net->socket, NULL, NULL)) < 0) {
      LOG_ERROR("Failed to accept connection");
      return;
    }

    log_remote_address(client);

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

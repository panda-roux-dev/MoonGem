#include "gemini.h"

#define _GNU_SOURCE

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cert.h"
#include "header.h"
#include "log.h"
#include "net.h"
#include "parse.h"
#include "status.h"
#include "uri.h"
#include "util.h"

#define CRLF "\r\n"
#define TAG_DELIMITER ";"
#define MIMETYPE_GEMTEXT "text/gemini; encoding=utf-8"
#define DEFAULT_FILE_MAX_WRITE 1 << 14

typedef struct context_t {
  request_t request;
  response_t response;
  FILE* file;
  struct evbuffer* out;
  SSL* ssl;
  bool error;
} context_t;

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

static void event_cb(struct bufferevent* bev, short evt, void* data) {
  if (evt & BEV_EVENT_EOF || evt & BEV_EVENT_ERROR) {
    LOG_DEBUG("Freeing connection buffer and context data");

    context_t* ctx = (context_t*)data;
    if (ctx != NULL) {
      request_t* req = &ctx->request;
      response_t* res = &ctx->response;

      if (req->cert != NULL) {
        destroy_client_cert(req->cert);
      }

      if (req->uri != NULL) {
        destroy_uri(req->uri);
      }

      CHECK_FREE(res->language);
      CHECK_FREE(res->meta);
      CHECK_FREE(res->mimetype);

      evbuffer_free(ctx->out);

      /*
      if (ctx->file != NULL) {
        fclose(ctx->file);
      }
      */

      free(ctx);
    }

    bufferevent_free(bev);
  }
}

static void end_response_cb(struct bufferevent* bev, void* data) {
  bufferevent_flush(bev, EV_WRITE, BEV_FINISHED);
  bufferevent_trigger_event(bev, BEV_EVENT_EOF | BEV_EVENT_WRITING, 0);
}

static void write_header(struct bufferevent* bev, context_t* ctx) {
  request_t* req = &ctx->request;
  response_t* res = &ctx->response;
  struct evbuffer* out = ctx->out;

  evbuffer_add_printf(out, "%d", res->status);

  // write meta
  bool has_tags = false;
  if (res->meta != NULL) {
    evbuffer_add_printf(out, " %s", res->meta);
    has_tags = true;
  }

  if (!ctx->error) {
    // write mimetype
    if (res->mimetype != NULL) {
      if (has_tags) {
        evbuffer_add(out, TAG_DELIMITER, sizeof(TAG_DELIMITER) - 1);
      }

      evbuffer_add_printf(out, " %s", res->mimetype);
      has_tags = true;
    }

    // write language
    if (res->language != NULL) {
      if (has_tags) {
        evbuffer_add(out, TAG_DELIMITER, sizeof(TAG_DELIMITER) - 1);
      }

      evbuffer_add_printf(out, " lang=%s", res->language);
    }
  }

  // terminate header
  evbuffer_add(out, CRLF, sizeof(CRLF) - 1);

  char header[1024] = {0};
  evbuffer_copyout(out, &header[0], sizeof(header) - 1);
  LOG_DEBUG("%s", &header[0]);
}

static void write_response_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;
  request_t* req = &ctx->request;
  response_t* res = &ctx->response;

  if (!ctx->error) {
    LOG_DEBUG("No error; serving file");

    if (req->uri->type == URI_TYPE_GEMTEXT) {
      LOG_DEBUG("Serving gemtext");

      // write the response header
      res->mimetype = strdup(MIMETYPE_GEMTEXT);
      write_header(bev, ctx);

      // parse the gemtext file and run any scripts found within
      parser_t* parser = create_doc_parser(req, res, ctx->file);
      parse_gemtext_doc(parser, ctx->out);
      destroy_doc_parser(parser);

      // write the response to the socket and terminate
      bufferevent_write_buffer(bev, ctx->out);
    } else {
      LOG_DEBUG("Serving non-gemtext file");

      res->mimetype = get_mimetype(req->uri->path);
      write_header(bev, ctx);
      struct evbuffer* buffer = bufferevent_get_output(bev);
      evbuffer_add_file(buffer, fileno(ctx->file), 0, -1);
    }
  } else {
    // write the response header
    write_header(bev, ctx);
  }

  bufferevent_setcb(bev, NULL, end_response_cb, event_cb, ctx);
  bufferevent_trigger(bev, EV_WRITE, 0);
}

static void read_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;
  request_t* req = &ctx->request;
  response_t* res = &ctx->response;

  // read the entire request into a buffer
  char request_buffer[MAX_URL_LENGTH + 2] = {0};
  size_t req_length = bufferevent_read(bev, &request_buffer[0],
                                       sizeof(request_buffer) / sizeof(char));

  // extract the uri
  req->uri = create_uri(&request_buffer[0]);

  if (req->uri == NULL) {
    res->status = STATUS_BAD_REQUEST;
    res->meta = strdup("Invalid URI");
    ctx->error = true;
  } else {
    // set the client certificate if one exists
    client_cert_t* cert =
        (client_cert_t*)SSL_get_ex_data(ctx->ssl, get_client_cert_index());
    if (cert != NULL) {
      req->cert = cert;
    }

    // check whether the requested file exists
    struct stat file_stat;
    if (stat(req->uri->path, &file_stat) != 0 || !S_ISREG(file_stat.st_mode)) {
      LOG_DEBUG("File %s does not exist", req->uri->path);
      res->status = STATUS_NOT_FOUND;
      res->meta = strdup("File does not exist");
      ctx->error = true;
    } else {
      LOG_DEBUG("File %s exists", req->uri->path);
      ctx->file = fopen(req->uri->path, "rb");
      if (ctx->file == NULL) {
        LOG_ERROR("Failed to open file at \"%s\"", req->uri->path);
        res->status = STATUS_TEMPORARY_FAILURE;
        res->meta = strdup("Failed to open file");
        ctx->error = true;
      }
    }
  }

  bufferevent_setcb(bev, NULL, write_response_cb, event_cb, ctx);
  bufferevent_trigger(bev, EV_WRITE, 0);
}

static void listener_cb(struct evconnlistener* listener, evutil_socket_t fd,
                        struct sockaddr* addr, int socklen, void* data) {
  SSL* ssl = SSL_new((SSL_CTX*)data);
  SSL_set_ex_data(ssl, get_client_cert_index(), create_client_cert());

  enum bufferevent_ssl_state state =
      fd != -1 ? BUFFEREVENT_SSL_ACCEPTING : BUFFEREVENT_SSL_CONNECTING;
  struct event_base* base = evconnlistener_get_base(listener);
  struct bufferevent* bev = bufferevent_openssl_socket_new(
      base, fd, ssl, state, BEV_OPT_CLOSE_ON_FREE);

  if (bev == NULL) {
    LOG_ERROR("Error constructing bufferevent!");
    event_base_loopbreak(base);
    return;
  }

  context_t* ctx = calloc(1, sizeof(context_t));
  ctx->ssl = ssl;
  ctx->out = evbuffer_new();
  ctx->response.status = STATUS_DEFAULT;

  bufferevent_setcb(bev, read_cb, NULL, event_cb, ctx);
  bufferevent_enable(bev, EV_READ);
}

static void term_cb(evutil_socket_t sig, short events, void* data) {
  LOG_DEBUG("Caught SIGINT; exiting...");

  struct timeval delay = {2, 0};
  event_base_loopexit((struct event_base*)data, &delay);
}

static void handle_gemini_requests(net_t* net) {
  struct event_base* base = event_base_new();
  if (base == NULL) {
    // TODO: log
    return;
  }

  int evflags =
      LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC;
  struct evconnlistener* listener =
      evconnlistener_new_bind(base, listener_cb, (void*)net->ssl_ctx, evflags,
                              -1, net->addr, net->addr_size);

  if (listener == NULL) {
    // TODO: log
    return;
  }

  struct event* signal_event =
      evsignal_new(base, SIGINT | SIGTERM | SIGKILL, term_cb, (void*)base);

  if (signal_event == NULL || event_add(signal_event, NULL) < 0) {
    // TODO: log
    return;
  }

  event_base_dispatch(base);

  evconnlistener_free(listener);
  event_free(signal_event);
  event_base_free(base);
}

void listen_for_gemini_requests(cli_options_t* options) {
  // set up socket + TLS
  net_t* net;
  if ((net = init_net(options)) == NULL) {
    LOG_ERROR("Failed to initialize socket for Gemini listener");
  } else {
    // begin listening for requests
    LOG("Listening for Gemini requests on port %d...", options->gemini_port);
    handle_gemini_requests(net);
    destroy_net(net);
  }
}

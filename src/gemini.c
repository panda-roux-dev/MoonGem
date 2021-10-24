#include "gemini.h"

#define GNU_SOURCE

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <magic.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cert.h"
#include "log.h"
#include "net.h"
#include "parse.h"
#include "status.h"
#include "uri.h"
#include "util.h"

#define CRLF "\r\n"
#define TAG_DELIMITER ";"
#define MAX_URL_LENGTH 1024
#define MIMETYPE_GEMTEXT "text/gemini; encoding=utf-8"
#define DEFAULT_MIMETYPE "application/octet-stream"

#define SIGNAL_HANDLERS_COUNT 4

static struct magic_set* magic;

typedef struct context_t {
  gemini_state_t gemini;
  file_info_t file;
  int chunk_size;
  struct evbuffer* out;
  SSL* ssl;
} context_t;

typedef struct request_common_state_t {
  SSL_CTX* ssl_ctx;
  cli_options_t* options;
} request_common_state_t;

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
      request_t* req = &ctx->gemini.request;

      if (req->cert != NULL) {
        destroy_client_cert(req->cert);
      }

      if (req->uri != NULL) {
        destroy_uri(req->uri);
      }

      evbuffer_free(ctx->out);

      if (ctx->file.ptr != NULL) {
        fclose(ctx->file.ptr);
      }

      free(ctx);
    }

    bufferevent_free(bev);
  }
}

static void end_response_cb(struct bufferevent* bev, void* data) {
  bufferevent_flush(bev, EV_WRITE, BEV_FINISHED);
  bufferevent_trigger_event(bev, BEV_EVENT_EOF | BEV_EVENT_WRITING, 0);
}

static void write_header(context_t* ctx) {
  gemini_state_t* gemini = &ctx->gemini;
  response_t* res = &gemini->response;
  struct evbuffer* out = ctx->out;

  evbuffer_add_printf(out, "%d", res->status);

  // write meta
  bool has_tags = false;
  if (response_has_meta(res)) {
    evbuffer_add_printf(out, " %s", &res->meta[0]);
    has_tags = true;
  }

  // write mimetype
  if (response_has_mime(res)) {
    if (has_tags) {
      evbuffer_add(out, TAG_DELIMITER, sizeof(TAG_DELIMITER) - 1);
    }

    evbuffer_add_printf(out, " %s", &res->mimetype[0]);
    has_tags = true;
  }

  // write language
  if (response_has_lang(res)) {
    if (has_tags) {
      evbuffer_add(out, TAG_DELIMITER, sizeof(TAG_DELIMITER) - 1);
    }

    evbuffer_add_printf(out, " lang=%s", &res->language[0]);
  }

  // terminate header
  evbuffer_add(out, CRLF, sizeof(CRLF) - 1);
}

static void serve_static_file_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;
  file_info_t* file = &ctx->file;

  size_t remaining = ctx->file.size - ctx->file.offset;

  // while there remains data to be buffered, load another block
  if (remaining > 0) {
    size_t length = remaining > ctx->chunk_size ? ctx->chunk_size : remaining;
    struct evbuffer_file_segment* segment =
        evbuffer_file_segment_new(file->fd, file->offset, length, 0);
    evbuffer_add_file_segment(ctx->out, segment, 0, -1);
    evbuffer_file_segment_free(segment);

    LOG_DEBUG("Buffering %zu bytes (%zu/%ld)", length,
              ctx->file.offset + length, ctx->file.size);

    file->offset += length;

    bufferevent_write_buffer(bev, ctx->out);
  } else {
    // the entire file has been sent
    bufferevent_setcb(bev, NULL, end_response_cb, event_cb, ctx);
    bufferevent_trigger(bev, EV_WRITE, 0);
  }
}

static void send_status_response(context_t* ctx, struct bufferevent* bev) {
  // write the response header
  write_header(ctx);

  // write the response to the socket and terminate
  bufferevent_write_buffer(bev, ctx->out);
  bufferevent_setcb(bev, NULL, end_response_cb, event_cb, ctx);
}

static void send_script_response(context_t* ctx, struct bufferevent* bev) {
  response_t* res = &ctx->gemini.response;

  LOG_DEBUG("Sending gemtext response");

  // parse the gemtext file and run any scripts found within
  parser_t* parser = create_doc_parser(&ctx->gemini, &ctx->file);
  struct evbuffer* rendered = evbuffer_new();
  parse_gemtext_doc(parser, rendered);
  destroy_doc_parser(parser);

  if (res->status != STATUS_DEFAULT) {
    // a status code was set by the script, so the rendered body should not be
    // sent to the client
    evbuffer_free(rendered);
    send_status_response(ctx, bev);
    return;
  }

  set_response_mime(res, MIMETYPE_GEMTEXT);

  // write the response header to a buffer, followed by the rendered gemtext
  write_header(ctx);
  evbuffer_add_buffer(ctx->out, rendered);
  evbuffer_free(rendered);

  // write the response to the socket and terminate
  bufferevent_write_buffer(bev, ctx->out);
  bufferevent_setcb(bev, NULL, end_response_cb, event_cb, ctx);
}

static void send_file_response(context_t* ctx, struct bufferevent* bev) {
  request_t* req = &ctx->gemini.request;
  response_t* res = &ctx->gemini.response;

  LOG_DEBUG("Sending non-gemtext file");

  const char* mimetype = magic_descriptor(magic, ctx->file.fd);

  if (mimetype == NULL) {
    LOG("Could not determine mimetype of %s; using the default (%s)",
        req->uri->path, DEFAULT_MIMETYPE);
    mimetype = DEFAULT_MIMETYPE;
  }

  set_response_mime(res, mimetype);

  // write response header
  write_header(ctx);
  bufferevent_write_buffer(bev, ctx->out);

  // serve the file
  bufferevent_setcb(bev, NULL, serve_static_file_cb, event_cb, ctx);
}

static void write_response_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;

  if (ctx->gemini.response.status == STATUS_DEFAULT) {
    if (ctx->gemini.request.uri->type == URI_TYPE_GEMTEXT) {
      send_script_response(ctx, bev);
    } else {
      send_file_response(ctx, bev);
    }
  } else {
    send_status_response(ctx, bev);
  }
}

static void read_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;
  request_t* req = &ctx->gemini.request;
  response_t* res = &ctx->gemini.response;
  file_info_t* file = &ctx->file;

  // read the entire request into a buffer
  char request_buffer[MAX_URL_LENGTH + 2] = {0};
  bufferevent_read(bev, &request_buffer[0],
                   sizeof(request_buffer) / sizeof(char));

  // extract the uri
  req->uri = create_uri(&request_buffer[0]);

  if (req->uri == NULL) {
    set_response_status(res, STATUS_BAD_REQUEST, META_BAD_REQUEST);
  } else {
    // set the client certificate if one exists
    client_cert_t* cert =
        (client_cert_t*)SSL_get_ex_data(ctx->ssl, CLIENT_CERT_INDEX);
    if (cert != NULL) {
      req->cert = cert;
    }

    // check whether the requested file exists
    struct stat st;
    if (stat(req->uri->path, &st) != 0 || !S_ISREG(st.st_mode)) {
      LOG_DEBUG("File %s does not exist", req->uri->path);
      set_response_status(res, STATUS_NOT_FOUND, META_NOT_FOUND);
    } else {
      LOG_DEBUG("File %s exists", req->uri->path);
      file->ptr = fopen(req->uri->path, "rb");
      if (file->ptr == NULL) {
        LOG_ERROR("Failed to open file at \"%s\"", req->uri->path);

        // if we can't open the file, it may be due to being denied permissions,
        // which is may have been intentional if the host doesn't want the files
        // to be served; tell the client they don't exist
        set_response_status(res, STATUS_NOT_FOUND, META_NOT_FOUND);
      } else {
        // file exists and was opened successfully
        file->fd = fileno(file->ptr);
        file->size = st.st_size;
      }
    }
  }

  bufferevent_setcb(bev, NULL, write_response_cb, event_cb, ctx);
  bufferevent_trigger(bev, EV_WRITE, 0);
}

static void listener_cb(struct evconnlistener* listener, evutil_socket_t fd,
                        struct sockaddr* addr, int socklen, void* data) {
  request_common_state_t* state = (request_common_state_t*)data;

  SSL* ssl = SSL_new(state->ssl_ctx);
  SSL_set_ex_data(ssl, CLIENT_CERT_INDEX, create_client_cert());

  enum bufferevent_ssl_state ssl_status =
      fd != -1 ? BUFFEREVENT_SSL_ACCEPTING : BUFFEREVENT_SSL_CONNECTING;
  struct event_base* base = evconnlistener_get_base(listener);
  struct bufferevent* bev = bufferevent_openssl_socket_new(
      base, fd, ssl, ssl_status, BEV_OPT_CLOSE_ON_FREE);

  if (bev == NULL) {
    LOG_ERROR("Error constructing bufferevent!");
    event_base_loopbreak(base);
    return;
  }

  context_t* ctx = calloc(1, sizeof(context_t));
  ctx->ssl = ssl;
  ctx->out = evbuffer_new();
  ctx->gemini.response.status = STATUS_DEFAULT;
  ctx->chunk_size = state->options->chunk_size;

  bufferevent_setcb(bev, read_cb, NULL, event_cb, ctx);
  bufferevent_enable(bev, EV_READ);
}

static void signal_shutdown_cb(evutil_socket_t sig, short events, void* data) {
  LOG_DEBUG("Caught shutdown signal; terminating...");
  event_base_loopexit((struct event_base*)data, NULL);
}

static void signal_kill_cb(evutil_socket_t sig, short events, void* data) {
  LOG_DEBUG("Caught SIGKILL, exiting immediately...");
  exit(-1);
}

static void signal_stop_cb(evutil_socket_t sig, short events, void* data) {
  LOG_DEBUG("Caught SIGSTOP, pausing I/O...");
  event_base_loopbreak((struct event_base*)data);
}

static void signal_continue_cb(evutil_socket_t sig, short events, void* data) {
  LOG_DEBUG("Caught SIGCONT, resuming I/O...");
  event_base_loopcontinue((struct event_base*)data);
}

static void add_signal_handlers(struct event** events,
                                struct event_base* base) {
  struct event* ev_sigint =
      evsignal_new(base, SIGINT, signal_shutdown_cb, (void*)base);
  struct event* ev_sigterm =
      evsignal_new(base, SIGTERM, signal_shutdown_cb, (void*)base);
  struct event* ev_sigquit =
      evsignal_new(base, SIGQUIT, signal_shutdown_cb, (void*)base);
  struct event* ev_sigcont =
      evsignal_new(base, SIGQUIT, signal_shutdown_cb, (void*)base);

  evsignal_add(ev_sigint, NULL);
  evsignal_add(ev_sigterm, NULL);
  evsignal_add(ev_sigquit, NULL);
  evsignal_add(ev_sigcont, NULL);

  int index = 0;
  events[index++] = ev_sigint;
  events[index++] = ev_sigterm;
  events[index++] = ev_sigquit;
  events[index++] = ev_sigcont;
}

static void free_signal_handlers(struct event** events) {
  for (int i = 0; i < SIGNAL_HANDLERS_COUNT; ++i) {
    event_free(events[i]);
  }
}

static void handle_gemini_requests(net_t* net, cli_options_t* options) {
  struct event_base* base = event_base_new();
  if (base == NULL) {
    LOG_ERROR("Failed to create event base!");
    return;
  }

  request_common_state_t state = {net->ssl_ctx, options};

  int evflags =
      LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC;
  struct evconnlistener* listener = evconnlistener_new_bind(
      base, listener_cb, (void*)&state, evflags, -1, net->addr, net->addr_size);

  if (listener == NULL) {
    LOG_ERROR("Failed to create event listener!");
    return;
  }

  struct event* events[SIGNAL_HANDLERS_COUNT];
  add_signal_handlers(&events[0], base);

  event_base_dispatch(base);

  evconnlistener_free(listener);
  free_signal_handlers(&events[0]);
  event_base_free(base);
}

void listen_for_gemini_requests(cli_options_t* options) {
  magic = magic_open(MAGIC_MIME | MAGIC_CHECK);
  if (magic == NULL) {
    LOG_ERROR("Failed to create libmagic database!");
    return;
  }

  magic_load(magic, NULL);

  // set up socket + TLS
  net_t* net;
  if ((net = init_net(options)) == NULL) {
    LOG_ERROR("Failed to initialize socket for Gemini listener");
  } else {
    // begin listening for requests
    LOG("Listening for Gemini requests on port %d...", options->gemini_port);
    handle_gemini_requests(net, options);
    destroy_net(net);
  }

  magic_close(magic);
}

void set_response_status(response_t* response, int code, const char* meta) {
  response->status = code;
  set_response_meta(response, meta);
}

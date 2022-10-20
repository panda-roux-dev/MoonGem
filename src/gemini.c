#include "gemini.h"

#include "script.h"

#define GNU_SOURCE

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <magic.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cert.h"
#include "log.h"
#include "net.h"
#include "parse.h"
#include "status.h"
#include "store.h"
#include "uri.h"
#include "util.h"

#define CRLF "\r\n"
#define TAG_DELIMITER "; "
#define MAX_URL_LENGTH 1024
#define MIMETYPE_GEMTEXT "text/gemini; encoding=utf-8"
#define DEFAULT_MIMETYPE "application/octet-stream"

#define LISTENER_EVFLAGS \
  (LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC)

typedef struct gemini_listener_t {
  struct evconnlistener* listener;
  cli_options_t* options;
  net_t* net;
  struct magic_set* magic;
  store_t* store;
} gemini_listener_t;

typedef struct context_t {
  gemini_context_t gemini;
  file_info_t file;
  struct evbuffer* early;
  struct evbuffer* out;
  SSL* ssl;
  cli_options_t* options;
  struct magic_set* magic;
  script_ctx_t* script_ctx;
  store_t* store;
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
      request_t* req = &ctx->gemini.request;

      if (req->cert != NULL) {
        destroy_client_cert(req->cert);
      }

      if (req->uri != NULL) {
        destroy_uri(req->uri);
      }

      evbuffer_free(ctx->out);

      if (ctx->early != NULL) {
        evbuffer_free(ctx->early);
      }

      if (ctx->file.ptr != NULL) {
        fclose(ctx->file.ptr);
      }

      free(ctx);
    }

    bufferevent_free(bev);
  }
}

static void end_response_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;
  cli_options_t* options = ctx->options;

  // run post-response or error scripts if applicable
  if (options->post_script_path != NULL &&
      !STATUS_IS_ERROR(ctx->gemini.response.status)) {
    if (ctx->script_ctx == NULL) {
      ctx->script_ctx = create_script_ctx(&ctx->gemini, ctx->store);
    }

    exec_script_file(ctx->script_ctx, options->post_script_path, ctx->out);
  } else if (options->post_script_path != NULL &&
             STATUS_IS_ERROR(ctx->gemini.response.status)) {
    if (ctx->script_ctx == NULL) {
      ctx->script_ctx = create_script_ctx(&ctx->gemini, ctx->store);
    }

    exec_script_file(ctx->script_ctx, options->error_script_path, ctx->out);
  }

  if (ctx->script_ctx != NULL) {
    destroy_script(ctx->script_ctx);
  }

  bufferevent_flush(bev, EV_WRITE, BEV_FINISHED);
  bufferevent_trigger_event(bev, BEV_EVENT_EOF | BEV_EVENT_WRITING, 0);
}

static void write_header(context_t* ctx) {
  gemini_context_t* gemini = &ctx->gemini;
  response_t* res = &gemini->response;
  struct evbuffer* out = ctx->out;

  evbuffer_add_printf(out, "%d ", res->status);

  // write meta
  bool has_tags = false;
  if (response_has_meta(res)) {
    evbuffer_add_printf(out, "%s", &res->meta[0]);
    has_tags = true;
  }

  // write mimetype
  if (response_has_mime(res)) {
    if (has_tags) {
      evbuffer_add(out, TAG_DELIMITER, sizeof(TAG_DELIMITER) - 1);
    }

    evbuffer_add_printf(out, "%s", &res->mimetype[0]);
    has_tags = true;
  }

  // write language
  if (response_has_lang(res)) {
    if (has_tags) {
      evbuffer_add(out, TAG_DELIMITER, sizeof(TAG_DELIMITER) - 1);
    }

    evbuffer_add_printf(out, "lang=%s", &res->language[0]);
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
    size_t chunk_size = ctx->options->chunk_size;
    size_t length = remaining > chunk_size ? chunk_size : remaining;
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
  parser_t* parser =
      create_doc_parser(&ctx->gemini, &ctx->file, ctx->script_ctx, ctx->store);
  struct evbuffer* rendered = evbuffer_new();
  parse_gemtext_doc(parser, rendered);

  // store a reference to the script context so that we can use it for running
  // post- or error-response scripts if needed
  ctx->script_ctx = parser->script_ctx;

  destroy_doc_parser(parser);

  if (res->interrupted || res->status != STATUS_DEFAULT) {
    // a status code was set by the script, so the rendered body should not be
    // sent to the client
    evbuffer_free(rendered);
    send_status_response(ctx, bev);
    return;
  }

  set_response_mime(res, MIMETYPE_GEMTEXT);

  // write the response header to a buffer, followed by the rendered gemtext
  write_header(ctx);

  // if the pre-request script wrote anything, then include that
  if (ctx->early != NULL) {
    evbuffer_add_buffer(ctx->out, ctx->early);
  }

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

  const char* mimetype = magic_descriptor(ctx->magic, ctx->file.fd);

  if (mimetype == NULL) {
    LOG("Could not determine mimetype of %s; using the default (%s)",
        req->uri->path, DEFAULT_MIMETYPE);
    mimetype = DEFAULT_MIMETYPE;
  }

  set_response_mime(res, mimetype);

  // write response header
  write_header(ctx);

  // if the pre-request script wrote anything, then include that
  if (ctx->early != NULL) {
    evbuffer_add_buffer(ctx->out, ctx->early);
  }

  bufferevent_write_buffer(bev, ctx->out);

  // serve the file
  bufferevent_setcb(bev, NULL, serve_static_file_cb, event_cb, ctx);
}

static void send_early_response(context_t* ctx, struct bufferevent* bev) {
  if (ctx->early == NULL) {
    return;
  }

  LOG_DEBUG("Pre-request script bypassed the rest of the response pipeline");

  // write response header
  write_header(ctx);

  // all we should have is the pre-response script's output buffer, so just
  // write that and end the response
  evbuffer_add_buffer(ctx->out, ctx->early);

  bufferevent_write_buffer(bev, ctx->out);
  bufferevent_setcb(bev, NULL, end_response_cb, event_cb, ctx);
}

static void write_response_cb(struct bufferevent* bev, void* data) {
  context_t* ctx = (context_t*)data;

  if (ctx->gemini.response.status == STATUS_DEFAULT) {
    if (ctx->gemini.response.interrupted) {
      send_early_response(ctx, bev);
    } else if (ctx->gemini.request.uri->type == URI_TYPE_GEMTEXT) {
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

    cli_options_t* options = ctx->options;

    // try to run a pre-request script if applicable
    bool pre_script_failed = false;
    if (options->pre_script_path != NULL) {
      ctx->script_ctx = create_script_ctx(&ctx->gemini, ctx->store);
      ctx->early = evbuffer_new();
      if (exec_script_file(ctx->script_ctx, options->pre_script_path,
                           ctx->early) != SCRIPT_OK) {
        pre_script_failed = true;
        set_response_status(res, STATUS_CGI_ERROR, META_CGI_ERROR);
        LOG_ERROR(
            "An error occurred during the pre-request script; bypassing the "
            "rest of the response");
      }
    }

    // if the pre-response script neither failed nor handled the request on its
    // own in some other way, continue handling the request
    if (!pre_script_failed && !res->interrupted) {
      struct stat st;
      if (stat(req->uri->path, &st) != 0 || !S_ISREG(st.st_mode)) {
        LOG_DEBUG("File %s does not exist", req->uri->path);
        set_response_status(res, STATUS_NOT_FOUND, META_NOT_FOUND);
      } else {
        LOG_DEBUG("File %s exists", req->uri->path);
        file_info_t* file = &ctx->file;
        file->ptr = fopen(req->uri->path, "rb");
        if (file->ptr == NULL) {
          LOG_ERROR("Failed to open file at \"%s\"", req->uri->path);

          // if we can't open the file, it may be due to being denied
          // permissions, which is may have been intentional if the host doesn't
          // want the files to be served; tell the client they don't exist
          set_response_status(res, STATUS_NOT_FOUND, META_NOT_FOUND);
        } else {
          // file exists and was opened successfully
          file->fd = fileno(file->ptr);
          file->size = st.st_size;
        }
      }
    }
  }

  bufferevent_setcb(bev, NULL, write_response_cb, event_cb, ctx);
  bufferevent_trigger(bev, EV_WRITE, 0);
}

static void listener_cb(struct evconnlistener* listener, evutil_socket_t fd,
                        struct sockaddr* addr, int socklen, void* data) {
  gemini_listener_t* gemini = (gemini_listener_t*)data;

  SSL* ssl = SSL_new(gemini->net->ssl_ctx);
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
  ctx->magic = gemini->magic;
  ctx->options = gemini->options;
  ctx->script_ctx = NULL;
  ctx->early = NULL;
  ctx->store = gemini->store;

  bufferevent_setcb(bev, read_cb, NULL, event_cb, ctx);
  bufferevent_enable(bev, EV_READ);
}

static struct magic_set* init_magic(void) {
  struct magic_set* magic = magic_open(MAGIC_MIME | MAGIC_CHECK);
  if (magic != NULL) {
    magic_load(magic, NULL);
  }
  return magic;
}

gemini_listener_t* init_gemini_listener(cli_options_t* options,
                                        struct event_base* evtbase) {
  gemini_listener_t* gemini = calloc(1, sizeof(gemini_listener_t));

  gemini->magic = init_magic();
  if (gemini->magic == NULL) {
    LOG_ERROR("Failed to load libmagic database");
    goto cleanup;
  }

  // set up socket + TLS
  gemini->net = init_net(options);
  if (gemini->net == NULL) {
    LOG_ERROR("Failed to initialize socket for Gemini listener");
    goto cleanup;
  }

  gemini->store = create_store(INITIAL_STORE_SIZE);

  gemini->options = options;

  gemini->listener =
      evconnlistener_new_bind(evtbase, listener_cb, gemini, LISTENER_EVFLAGS,
                              -1, gemini->net->addr, gemini->net->addr_size);
  if (gemini->listener == NULL) {
    LOG_ERROR("Failed to create event listener");
    goto cleanup;
  }

  return gemini;

cleanup:
  cleanup_gemini_listener(gemini);
  return NULL;
}

void cleanup_gemini_listener(gemini_listener_t* gemini) {
  if (gemini == NULL) {
    return;
  }

  if (gemini->listener != NULL) {
    evconnlistener_free(gemini->listener);
  }

  if (gemini->store != NULL) {
    destroy_store(gemini->store);
  }

  if (gemini->net != NULL) {
    destroy_net(gemini->net);
  }

  if (gemini->magic != NULL) {
    magic_close(gemini->magic);
  }

  free(gemini);
}

void set_response_status(response_t* response, int code, const char* meta) {
  response->status = code;
  set_response_meta(response, meta);
}

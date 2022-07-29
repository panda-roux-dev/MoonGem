#include <errno.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "gemini.h"
#include "log.h"
#include "options.h"
#include "parse.h"
#include "script.h"
#include "signals.h"
#include "store.h"
#include "uri.h"

int run_server_mode(cli_options_t* options);

int run_script_mode(cli_options_t* options);

int main(int argc, const char** argv) {
  if (init_uri_regex() != 0 || init_parser_regex() != 0) {
    LOG_ERROR("Failed to compile regexp");
    return EXIT_FAILURE;
  }

  cli_options_t* options = parse_options(argc, argv);
  if (options == NULL) {
    return EXIT_FAILURE;
  }

#ifndef MOONGEM_ALLOW_ROOT
  if (getuid() == 0) {
    LOG_ERROR("MoonGem should not be run as root!  Terminating...");
    return EXIT_FAILURE;
  }
#endif

  int status = options->script_mode_path == NULL ? run_server_mode(options)
                                                 : run_script_mode(options);

  destroy_options(options);
  cleanup_uri_regex();
  cleanup_parser_regex();

  return status;
}

int run_server_mode(cli_options_t* options) {
  // move the working directory to the user-defined root path if provided
  if (options->root != NULL) {
    chdir(options->root);
  }

  struct event_base* evtbase = event_base_new();
  if (evtbase == NULL) {
    LOG_ERROR("Failed to initialize event handler state");
    return EXIT_FAILURE;
  }

  struct event** evts = init_signal_handlers(evtbase);
  if (evts == NULL) {
    LOG_ERROR("Failed to initialize signal handlers");
    event_base_free(evtbase);
    return EXIT_FAILURE;
  }

  gemini_listener_t* gemini = init_gemini_listener(options, evtbase);
  if (gemini == NULL) {
    LOG_ERROR("Failed to initialize gemini listener");
    cleanup_signal_handlers(evts);
    event_base_free(evtbase);
  }

  // block while requests are handled
  event_base_dispatch(evtbase);

  cleanup_gemini_listener(gemini);
  cleanup_signal_handlers(evts);
  event_base_free(evtbase);

  return EXIT_SUCCESS;
}

int run_script_mode(cli_options_t* options) {
  gemini_context_t ctx = {0};

  store_t* store = create_store(INITIAL_STORE_SIZE);

  // parse the URI provided via the command-line if provided
  ctx.request.uri = create_uri(options->script_mode_input);

  // create a new script context and output buffer, then execute the script file
  script_ctx_t* script_ctx = create_script_ctx(&ctx, store);
  struct evbuffer* buffer = evbuffer_new();
  script_result_t result =
      exec_script_file(script_ctx, options->script_mode_path, buffer);

  // write to STDOUT
  evbuffer_write(buffer, STDOUT_FILENO);

  evbuffer_free(buffer);
  destroy_script(script_ctx);
  destroy_uri(ctx.request.uri);
  destroy_store(store);

  return result == SCRIPT_OK;
}

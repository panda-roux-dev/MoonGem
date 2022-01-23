#include <errno.h>
#include <event2/event.h>
#include <unistd.h>

#include "gemini.h"
#include "log.h"
#include "options.h"
#include "signals.h"

int main(int argc, const char** argv) {
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

  destroy_options(options);

  return EXIT_SUCCESS;
}

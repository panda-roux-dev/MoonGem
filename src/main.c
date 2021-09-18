#include <errno.h>
#include <unistd.h>

#include "gemini.h"
#include "log.h"
#include "options.h"
#include "runtime.h"

// if HTTP proxying isn't disabled, then include the appropriate header and
// execute any HTTP-related logic
#ifndef DISABLE_HTTP
#include "http.h"
#define HTTP(expr) expr
#else
#define HTTP(expr) ((void)0)
#endif

int main(int argc, const char** argv) {
  cli_options_t* options = parse_options(argc, argv);
  if (options == NULL) {
    return EXIT_FAILURE;
  }

  if (!check_privileges()) {
    // don't run if we can't drop privileges
    return EXIT_FAILURE;
  }

  // move the working directory to the user-defined root path if provided
  if (options->root != NULL) {
    chdir(options->root);
  }

  // handle signals
  begin_signal_handler();

  HTTP(http_t* http = listen_for_http_requests(options));

  // control flow blocks here until the gemini thread terminates
  listen_for_gemini_requests(options);

  HTTP(destroy_http(http));

  destroy_options(options);

  return EXIT_SUCCESS;
}

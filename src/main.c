#include <errno.h>
#include <unistd.h>

#include "gemini.h"
#include "log.h"
#include "options.h"
#include "parse.h"
#include "uri.h"

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

  // compile the URI regex
  if (init_uri_regex() != 0) {
    return EXIT_FAILURE;
  }

  // compile the parser regex
  if (init_parser_regex() != 0) {
    return EXIT_FAILURE;
  }

  // control flow blocks here until the gemini thread terminates
  listen_for_gemini_requests(options);

  destroy_options(options);
  cleanup_uri_regex();
  cleanup_parser_regex();

  return EXIT_SUCCESS;
}

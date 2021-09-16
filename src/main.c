#include <stdlib.h>
#include <unistd.h>

#include "gemini.h"
#include "log.h"
#include "util.h"

int main(int argc, const char** argv) {
  if (argc < 3) {
    LOG_ERROR(
        "Missing arguments!  Usage: moongem <cert-path> <key-path> [path]");
    return EXIT_FAILURE;
  }

  cli_options_t options = {realpath(argv[1], NULL), realpath(argv[2], NULL)};

  if (!check_privileges()) {
    // don't run if we can't drop privileges
    return EXIT_FAILURE;
  }

  // move the working directory to the path in the third argument, if present
  if (argc >= 4) {
    char* cwd = realpath(argv[3], NULL);
    chdir(cwd);
  }

  // handle SIGPIPE events
  install_signal_handler();

  listen_for_gemini_requests(&options);

  free(options.cert_path);
  free(options.key_path);

  return EXIT_SUCCESS;
}

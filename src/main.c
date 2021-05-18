#include <stdlib.h>
#include <unistd.h>

#include "handler.h"
#include "log.h"
#include "util.h"

#define DEFAULT_PORT 1965
#define VAR_MOONGEM_PORT "MOONGEM_PORT"

int main(int argc, const char** argv) {
  if (argc < 3) {
    LOG_ERROR(
        "Missing arguments!  Usage: moongem <cert-path> <key-path> [path]");
    return EXIT_FAILURE;
  }

  if (!check_privileges()) {
    // don't run if we can't drop privileges
    return EXIT_FAILURE;
  }

  int port = get_env_int(VAR_MOONGEM_PORT, DEFAULT_PORT);

  // set up socket + TLS
  net_t* sock;
  if ((sock = init_socket(port, argv[1], argv[2])) == NULL) {
    LOG_ERROR("Failed to intiialize network socket.  Terminating...");
    return EXIT_FAILURE;
  }

  // move the working directory to the path in the third argument, if present
  if (argc >= 4) {
    char* cwd = realpath(argv[3], NULL);
    chdir(cwd);
  }

  // begin listening for requests
  handle_requests(sock, handle_request);

  destroy_socket(sock);

  return EXIT_SUCCESS;
}

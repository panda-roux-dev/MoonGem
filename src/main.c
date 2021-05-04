#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "net.h"
#include "parse.h"
#include "status.h"
#include "util.h"

#define PORT 1965

static callback_result_t handle_request(const request_t* request,
                                        response_t* response) {
  FILE* file = fopen(request->path + 1, "rb");
  if (file == NULL) {
    response->status = STATUS_NOT_FOUND;
    response->meta = strdup("File does not exist");
    return ERROR;
  }

  callback_result_t result = parse_response_from_file(file, request, response);
  fclose(file);

  return result;
}

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

  // set up socket + TLS
  net_t* sock;
  if ((sock = init_socket(PORT, argv[1], argv[2])) == NULL) {
    LOG_ERROR("Failed to intiialize network socket.  Terminating...");
    return EXIT_FAILURE;
  }

  if (argc >= 4) {
    char* cwd = realpath(argv[3], NULL);
    LOG_DEBUG("Changed working directory to %s", cwd);
    chdir(cwd);
  }

  // begin listening for requests
  handle_requests(sock, handle_request);

  destroy_socket(sock);

  return EXIT_SUCCESS;
}

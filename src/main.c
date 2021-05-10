#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "net.h"
#include "parse.h"
#include "status.h"
#include "util.h"

#define PORT 1965
#define DEFAULT_DOCUMENT "index.gmi"
#define EXT_GMI ".gmi"
#define VAR_MOONGEM_PORT "MOONGEM_PORT"

#define INVALID_URL_PATTERNS "/..", "/.", "/../", "/./", "~/", "$"

static bool path_is_gmi(const char* path) {
  if (path == NULL) {
    return false;
  }

  return strcmp(strrchr(path, '.'), EXT_GMI) == 0;
}

static bool is_dir(const char* path) { return strrchr(path, '.') == NULL; }

static char* append_default_doc(const request_t* request) {
  size_t path_buf_len =
      (request->path_length) + sizeof(DEFAULT_DOCUMENT) / sizeof(char);
  char* path = malloc((path_buf_len + 1) * sizeof(char));
  if (path == NULL) {
    LOG_ERROR("Failed to append default document name to URL");
    return NULL;
  }

  memcpy(path, request->path, request->path_length * sizeof(char));
  if (request->path[request->path_length - 1] != '/') {
    path[request->path_length] = '/';
    memcpy(&path[request->path_length + 1], &DEFAULT_DOCUMENT[0],
           sizeof(DEFAULT_DOCUMENT));
  } else {
    memcpy(&path[request->path_length], &DEFAULT_DOCUMENT[0],
           sizeof(DEFAULT_DOCUMENT));
  }

  path[path_buf_len] = '\0';

  return path;
}

static bool path_is_illegal(const char* path) {
  const char* bad_strings[] = {INVALID_URL_PATTERNS};
  for (int i = 0; i < sizeof(bad_strings) / sizeof(char*); ++i) {
    if (strstr(path, bad_strings[i]) != NULL) {
      return true;
    }
  }

  return false;
}

static callback_result_t handle_request(const request_t* request,
                                        response_t* response) {
  char* path;
  if (is_dir(request->path)) {
    path = append_default_doc(request);
  } else {
    path = strndup(request->path, request->path_length);
  }

  if (path_is_illegal(path)) {
    // don't permit directory browsing
    response->status = STATUS_BAD_REQUEST;
    response->meta = strdup("Invalid URL");
    free(path);
    return ERROR;
  }

  FILE* file = fopen(path + 1, "rb");
  if (file == NULL) {
    response->status = STATUS_NOT_FOUND;
    response->meta = strdup("File does not exist");
    free(path);
    return ERROR;
  }

  callback_result_t result;

  if (path_is_gmi(path)) {
    // parse .gmi files into gemtext

    result = parse_response_from_file(file, request, response);
  } else {
    // serve any file that doesn't have a .gmi extension in a simple static
    // operation

    result = serve_static(path, file, response);
  }

  free(path);

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

  int port = PORT;

  // check environment variable for user-specified network port
  char* port_var = getenv(VAR_MOONGEM_PORT);
  if (port_var != NULL) {
    port = (int)atol(port_var);
    if (port == 0) {
      LOG_ERROR("Invalid value \"%s\" provided for %s.  Terminating...",
                port_var, VAR_MOONGEM_PORT);
      return EXIT_FAILURE;
    }
  }

  // set up socket + TLS
  net_t* sock;
  if ((sock = init_socket(port, argv[1], argv[2])) == NULL) {
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

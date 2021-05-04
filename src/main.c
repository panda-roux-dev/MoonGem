#include <stdbool.h>
#include <stdio.h>
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

static callback_result_t handle_request(const request_t* request,
                                        response_t* response) {
  char* path;
  if (is_dir(request->path)) {
    path = append_default_doc(request);
  } else {
    path = strndup(request->path, request->path_length);
  }

  LOG("Path: %s", path);

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
    //
    // not using default path and the path isn't .gmi; so we need to infer
    // mimetype

    response->mimetype = get_mimetype(path);
    response->status = STATUS_SUCCESS;

    fseek(file, 0, SEEK_END);
    response->body_length = ftell(file);
    response->body = malloc(response->body_length * sizeof(char));
    if (response->body == NULL) {
      LOG_ERROR("Failed to allocate %zu bytes of memory for %s",
                response->body_length, path);
      response->status = STATUS_PERMANENT_FAILURE;
      response->meta = strdup("File is too large for the server to handle");
      result = ERROR;
    } else {
      fseek(file, 0, SEEK_SET);
      fread(response->body, sizeof(char), response->body_length, file);
      result = OK;
    }
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

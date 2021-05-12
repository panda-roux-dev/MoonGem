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

#define DEFAULT_PORT 1965
#define VAR_MOONGEM_PORT "MOONGEM_PORT"
#define MIMETYPE_GEMTEXT "text/gemini; encoding=utf-8"

static callback_result_t handle_request(const request_t* request,
                                        response_t* response,
                                        response_body_builder_t* builder) {
  // if the requested path is a directory, append the default document
  // 'index.gmi' onto it for the purposes of file IO
  char* path = is_dir(request->path)
                   ? append_default_doc(request)
                   : strndup(request->path, request->path_length);

  callback_result_t result = ERROR;

  if (path_is_illegal(path)) {
    // don't permit directory browsing
    set_response_status(response, STATUS_BAD_REQUEST, "Invalid URL");
    goto finish;
  }

  FILE* file = fopen(path + 1, "rb");
  if (file == NULL) {
    set_response_status(response, STATUS_NOT_FOUND, strerror(errno));
    goto finish;
  }

  if (path_is_gmi(path)) {
    // parse .gmi files into gemtext

    parser_t* parser = create_doc_parser(request, response, file);
    init_body_builder(builder, response_body_parser_cb,
                      response_parser_cleanup_cb, parser);
    response->mimetype = strdup(MIMETYPE_GEMTEXT);
    result = OK;
  } else {
    // serve any file that doesn't have a .gmi extension in a simple static
    // operation

    init_body_builder(builder, response_body_static_file_cb,
                      response_static_file_cleanup_cb, file);
    response->mimetype = get_mimetype(path + 1);
    result = OK;
  }

finish:
  free(path);
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

  int port = get_env_int(VAR_MOONGEM_PORT, DEFAULT_PORT);

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

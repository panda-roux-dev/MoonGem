#include "handler.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"
#include "status.h"
#include "util.h"

#define MIMETYPE_GEMTEXT "text/gemini; encoding=utf-8"

callback_result_t handle_request(const request_t* request, response_t* response,
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

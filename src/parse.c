#include "parse.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "net.h"
#include "script.h"
#include "status.h"
#include "util.h"

#define LINE_SCRIPT_START "-<<"
#define LINE_SCRIPT_END ">>-"
#define DELIM_SIZE ((sizeof(LINE_SCRIPT_START) - 1) / sizeof(char))
#define LINE_BUFFER_SIZE 2048
#define MAX_LANGUAGE_LEN 32

typedef enum { TEXT, SCRIPT_START, SCRIPT_END } line_type_t;

typedef struct doc_state_t {
  text_buffer_t* output_buffer;
  text_buffer_t* script_buffer;
  script_ctx_t* script_ctx;
  bool script_mode;
} doc_state_t;

static doc_state_t* create_doc_state(const request_t* request,
                                     response_t* response) {
  doc_state_t* state = (doc_state_t*)malloc(sizeof(doc_state_t));
  state->output_buffer = create_buffer();
  state->script_buffer = create_buffer();
  state->script_ctx = init_script(request, response);
  state->script_mode = false;
  return state;
}

static void destroy_doc_state(doc_state_t* state) {
  if (state != NULL) {
    destroy_buffer(state->output_buffer);
    destroy_buffer(state->script_buffer);
    destroy_script(state->script_ctx);
    free(state);
  }
}

static line_type_t get_line_type(char* line) {
  if (strncmp(line, LINE_SCRIPT_START, DELIM_SIZE) == 0) {
    return SCRIPT_START;
  }

  if (strncmp(line, LINE_SCRIPT_END, DELIM_SIZE) == 0) {
    return SCRIPT_END;
  }

  return TEXT;
}

/*
 * Returns false upon error
 */
static bool parse_line(char* line, doc_state_t* state) {
  text_buffer_t* scr_buf = state->script_buffer;
  text_buffer_t* out_buf = state->output_buffer;

  switch (get_line_type(line)) {
    case TEXT: {
      text_buffer_t* buf = state->script_mode ? scr_buf : out_buf;
      size_t line_len = strnlen(line, LINE_BUFFER_SIZE / sizeof(char));
      if (buffer_append(buf, line, line_len) == BUFFER_APPEND_FAILURE) {
        LOG_ERROR("Failed to append line to buffer");
        return false;
      }
      break;
    }
    case SCRIPT_START: {
      // enable script-mode and clear the script buffer
      state->script_mode = true;
      clear_buffer(scr_buf);
      break;
    }
    case SCRIPT_END: {
      // disable script-mode
      state->script_mode = false;
      if (scr_buf->length == 0) {
        break;
      }

      // run the script contained in state->script_buffer and append the
      // resulting string to the output buffer
      script_ctx_t* ctx = state->script_ctx;
      if (run_script(ctx, scr_buf->buffer) != 0) {
        LOG_ERROR("Failed to run script");
        return false;
      }

      if (state->script_ctx->result != NULL) {
        if (state->script_ctx->result_len > 0) {
          buffer_append(out_buf, ctx->result, ctx->result_len);
        }
      }

      break;
    }
  }

  return true;
}

parser_t* create_doc_parser(const request_t* request, response_t* response,
                            FILE* file) {
  parser_t* parser = (parser_t*)malloc(sizeof(parser_t));
  parser->doc_state = create_doc_state(request, response);
  parser->file = file;
  parser->response = response;
  parser->processed = false;
  parser->written = 0;
  return parser;
}

void destroy_doc_parser(parser_t* parser) {
  if (parser != NULL) {
    destroy_doc_state(parser->doc_state);
    fclose(parser->file);
    free(parser);
  }
}

static size_t write_to_body_buffer(size_t max, size_t* written, char* buffer,
                                   text_buffer_t* rendered) {
  size_t remaining = rendered->length - *written;
  size_t len = remaining < max ? remaining : max;
  memcpy(buffer, &rendered->buffer[*written], len * sizeof(char));
  *written += len;
  return len;
}

size_t response_body_parser_cb(size_t max, char* buffer, void* data) {
  if (data == NULL) {
    return 0;
  }

  parser_t* parser = (parser_t*)data;
  text_buffer_t* rendered = parser->doc_state->output_buffer;

  if (parser->processed) {
    // document parsed; return the next batch from the output buffer
    if (parser->written >= rendered->length) {
      // finished
      return 0;
    }

    return write_to_body_buffer(max, &parser->written, buffer, rendered);
  }  // document not yet parsed, so read it and return the first batch from the
  // output buffer

  bool line_error = false;
  char line[LINE_BUFFER_SIZE];
  while (fgets(&line[0], sizeof(line) / sizeof(char), parser->file)) {
    if (!parse_line(&line[0], parser->doc_state)) {
      line_error = true;
      break;
    }

    if (parser->response->interrupted) {
      // script interrupted the response; stop proccessing lines
      break;
    }
  }

  // scripts have been run and the document has been fully rendered, so we
  // don't need to come back here
  parser->processed = true;

  if (line_error) {
    // script error; bail without writing any body
    parser->response->status = STATUS_CGI_ERROR;
    parser->response->meta = strdup("Error reading file");
    return 0;
  }

  // no error; write first chunk to body buffer
  return write_to_body_buffer(max, &parser->written, buffer, rendered);
}

void response_parser_cleanup_cb(void* data) {
  if (data != NULL) {
    destroy_doc_parser((parser_t*)data);
  }
}

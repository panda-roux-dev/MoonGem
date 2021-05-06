#include "parse.h"

#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "script.h"
#include "status.h"
#include "util.h"

#define LINE_SCRIPT_START "-<<"
#define LINE_SCRIPT_END ">>-"
#define DELIM_SIZE ((sizeof(LINE_SCRIPT_START) - 1) / sizeof(char))
#define LINE_BUFFER_SIZE 2048
#define MIMETYPE_GEMTEXT "text/gemini; encoding=utf-8"
#define MAX_LANGUAGE_LEN 32

typedef enum { TEXT, SCRIPT_START, SCRIPT_END } line_type_t;

typedef struct {
  text_buffer_t* output_buffer;
  text_buffer_t* script_buffer;
  script_ctx_t* script_ctx;
  bool script_mode;
} doc_state_t;

static doc_state_t create_doc_state(const char* path) {
  doc_state_t state = {create_buffer(), create_buffer(), init_script(path),
                       false};
  return state;
}

static void destroy_doc_state(doc_state_t* state) {
  destroy_buffer(state->output_buffer);
  destroy_buffer(state->script_buffer);
  destroy_script(state->script_ctx);
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

int parse_response_from_file(FILE* file, const request_t* request,
                             response_t* response) {
  bool line_error = false;
  doc_state_t state = create_doc_state(request->path);
  char buffer[LINE_BUFFER_SIZE];
  while (fgets(&buffer[0], sizeof(buffer) / sizeof(char), file)) {
    if (!parse_line(&buffer[0], &state)) {
      line_error = true;
      break;
    }
  }

  callback_result_t result;
  if (line_error) {
    response->status = STATUS_CGI_ERROR;
    response->meta = strdup("Error reading file");
    result = ERROR;
  } else {
    response->body =
        strndup(state.output_buffer->buffer, state.output_buffer->length);
    response->body_length = state.output_buffer->length;
    response->status = STATUS_SUCCESS;
    response->mimetype = strdup(MIMETYPE_GEMTEXT);
    if (state.script_ctx->language != NULL) {
      response->language =
          strndup(state.script_ctx->language, MAX_LANGUAGE_LEN);
    }
    result = OK;
  }

  destroy_doc_state(&state);

  return result;
}


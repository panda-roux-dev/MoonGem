#include "parse.h"

#include <event2/buffer.h>
#include <pcre2posix.h>
#include <string.h>

#include "gemini.h"
#include "log.h"
#include "script.h"
#include "status.h"
#include "util.h"

#define SCRIPT_BEGIN_TOKEN "{{"
#define SCRIPT_END_TOKEN "}}"

#define SCRIPT_PATTERN (SCRIPT_BEGIN_TOKEN "(.*?)" SCRIPT_END_TOKEN)
#define SCRIPT_PATTERN_PARTS 2
#define SCRIPT_PATTERN_PART_BLOCK 0
#define SCRIPT_PATTERN_PART_BODY 1

#define REGEX_ERROR_MAX_LENGTH (1 << 8)

static regex_t parser_regexp;

static char* slurp_file_from_parser(parser_t* parser) {
  file_info_t* file = parser->file;

  // read entire file into memory and add a null-terminator
  char* body = malloc((file->size + 1) * sizeof(char));
  fseek(file->ptr, 0, SEEK_SET);
  fread(body, sizeof(char), file->size, file->ptr);
  body[file->size] = '\0';

  return body;
}

static bool find_next_script_block(char* cursor, regmatch_t* matches) {
  int result = regexec(&parser_regexp, cursor, SCRIPT_PATTERN_PARTS, matches,
                       REG_NOTBOL | REG_NOTEOL | REG_NOTEMPTY);
  return result == 0;
}

int init_parser_regex(void) {
  int status = regcomp(&parser_regexp, SCRIPT_PATTERN, REG_ICASE | REG_DOTALL);

  LOG_DEBUG("Script pattern: %s", SCRIPT_PATTERN);

  if (status != 0) {
    char msg[REGEX_ERROR_MAX_LENGTH] = {0};
    regerror(status, &parser_regexp, &msg[0], sizeof(msg));
    LOG_ERROR("Failed to compile script regex: %s", &msg[0]);
    return -1;
  }

  return 0;
}

void cleanup_parser_regex(void) { regfree(&parser_regexp); }

parser_t* create_doc_parser(gemini_context_t* gemini, file_info_t* file,
                            script_ctx_t* script_ctx) {
  parser_t* parser = (parser_t*)malloc(sizeof(parser_t));
  parser->gemini = gemini;
  parser->file = file;
  parser->script_ctx =
      script_ctx;  // may be NULL if no pre-request script was run

  return parser;
}

void parse_gemtext_doc(parser_t* parser, struct evbuffer* buffer) {
  response_t* response = &parser->gemini->response;

  regmatch_t matches[SCRIPT_PATTERN_PARTS] = {0};

  char* body = slurp_file_from_parser(parser);
  char* cursor = body;

  while (find_next_script_block(cursor, &matches[0])) {
    regmatch_t* block = &matches[SCRIPT_PATTERN_PART_BLOCK];
    regmatch_t* script = &matches[SCRIPT_PATTERN_PART_BODY];

    if (block->rm_so > 0) {
      // copy everything from the cursor up to the start of the current block
      // into the buffer
      evbuffer_add(buffer, cursor, block->rm_so);
    }

    if (parser->script_ctx == NULL) {
      // create the scripting environment if it doesn't exist
      parser->script_ctx = create_script_ctx(parser->gemini);
    }

    if (exec_script(parser->script_ctx, &cursor[script->rm_so],
                    script->rm_eo - script->rm_so, buffer) == SCRIPT_ERROR) {
      response->status = STATUS_CGI_ERROR;
      set_response_meta(response, "Script error");
      goto done;
    }

    if (response->interrupted) {
      // the script executed a halting method call (i.e. status code response),
      // so we should stop parsing the document and return immediately
      break;
    }

    cursor += block->rm_eo + 1;
  }

  if (!response->interrupted) {
    // copy any remaining gemtext into the result
    evbuffer_add(buffer, cursor,
                 (uintptr_t)(body) + parser->file->size - (uintptr_t)cursor);
  }

done:
  free(body);
}

void destroy_doc_parser(parser_t* parser) {
  if (parser != NULL) {
    // don't free the script context here; we may need to use it for post- or
    // error-response scripts

    free(parser);
  }
}

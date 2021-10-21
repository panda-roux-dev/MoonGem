#include "parse.h"

#include <event2/buffer.h>
#include <pcre2posix.h>
#include <string.h>

#include "gemini.h"
#include "log.h"
#include "script.h"
#include "status.h"

#define SCRIPT_BEGIN_TOKEN "{{"
#define SCRIPT_END_TOKEN "}}"

#define SCRIPT_PATTERN (SCRIPT_BEGIN_TOKEN "(.*?)" SCRIPT_END_TOKEN)
#define SCRIPT_PATTERN_PARTS 2
#define SCRIPT_PATTERN_PART_BLOCK 0
#define SCRIPT_PATTERN_PART_BODY 1

static regex_t parser_regexp;
static char regex_error[512] = {0};

int init_parser_regex(void) {
  int status = regcomp(&parser_regexp, SCRIPT_PATTERN, REG_ICASE | REG_DOTALL);

  LOG_DEBUG("Script pattern: %s", SCRIPT_PATTERN);

  if (status != 0) {
    regerror(status, &parser_regexp, &regex_error[0], sizeof(regex_error));
    LOG_ERROR("Failed to compile script regex: %s", &regex_error[0]);
    return -1;
  }

  return 0;
}

void cleanup_parser_regex(void) { regfree(&parser_regexp); }

parser_t* create_doc_parser(const request_t* request, response_t* response,
                            FILE* file) {
  parser_t* parser = (parser_t*)malloc(sizeof(parser_t));
  parser->file = file;
  parser->request = request;
  parser->response = response;
  parser->script_ctx = NULL;

  return parser;
}

void parse_gemtext_doc(parser_t* parser, struct evbuffer* buffer) {
  response_t* response = parser->response;
  const request_t* request = parser->request;

  FILE* file = parser->file;

  fseek(file, 0, SEEK_END);
  size_t file_length = ftell(file);
  if (file_length == 0) {
    return;
  }

  // read the entire file into a buffer
  char* file_contents = malloc((file_length + 1) * sizeof(char));
  fseek(file, 0, SEEK_SET);
  fread(file_contents, sizeof(char), file_length, file);
  file_contents[file_length] = '\0';

  // TODO: move block into a separate method
  size_t file_offset = 0;
  regmatch_t matches[SCRIPT_PATTERN_PARTS] = {0};
  while (file_offset < file_length - 1) {
    int match_res = regexec(&parser_regexp, &file_contents[file_offset],
                            SCRIPT_PATTERN_PARTS, &matches[0],
                            REG_NOTBOL | REG_NOTEOL | REG_NOTEMPTY);
    if (match_res != 0) {
      if (match_res == REG_NOMATCH) {
        // no more script blocks
        break;
      } else {
        pcre2_regerror(match_res, &parser_regexp, &regex_error[0],
                       sizeof(regex_error));
        LOG_ERROR("Failed to execute script pattern regex: %s",
                  &regex_error[0]);
        response->status = STATUS_PERMANENT_FAILURE;
        response->meta = strdup("PCRE Error");
        goto done;
      }
    }

    regmatch_t* match_block = &matches[SCRIPT_PATTERN_PART_BLOCK];
    regmatch_t* match_body = &matches[SCRIPT_PATTERN_PART_BODY];

    if (match_block->rm_eo == -1) {
      break;
    }

    // TODO: fix the order of this whole loop body aaaaaaaaaaaaaaaaaaaaaaaaaaa

    asdfsafdsafdsaff if (match_block->rm_so > file_offset) {
      // copy everything from the beginning of the file or end of previous
      // match up to the start of the current match into the buffer
      evbuffer_add(buffer, &file_contents[file_offset],
                   match_block->rm_so - file_offset);
    }

    char* body_contents = &file_contents[match_body->rm_so + file_offset];
    file_offset = match_block->rm_eo;

    size_t script_len = match_body->rm_eo - match_body->rm_so;
    if (script_len <= 0) {
      // skip zero-length scripts
      continue;
    }

    if (parser->script_ctx == NULL) {
      parser->script_ctx = create_script_ctx(request, response);
    }

    if (exec_script(parser->script_ctx, body_contents, script_len, buffer) ==
        SCRIPT_ERROR) {
      response->status = STATUS_CGI_ERROR;
      response->meta = strdup("Script Error");
      goto done;
    }

    LOG_DEBUG("Ran a script of length %zu", script_len);
  }

  // copy any remaining gemtext into the result
  if (file_offset < file_length - 1) {
    evbuffer_add(buffer, &file_contents[file_offset],
                 file_length - file_offset);
  }

done:
  free(file_contents);
}

void destroy_doc_parser(parser_t* parser) {
  if (parser != NULL) {
    destroy_script(parser->script_ctx);
    fclose(parser->file);
    free(parser);
  }
}

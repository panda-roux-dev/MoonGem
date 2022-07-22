#include "options.h"

#include <argparse.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

#define DEFAULT_FILE_CHUNK_SIZE (1 << 14)

#define DESCRIPTION                                                   \
  "A Gemini server with inline Lua scripting for generating dynamic " \
  "content"
#define ADDITIONAL                                                   \
  "Developed by panda-roux.  Source and documentation can be found " \
  "at https://git.panda-roux.dev/MoonGem"

static const char* const usage[] = {
    "moongem [options] --cert=cert.pem --key=key.pem",
    "moongem --script=script.lua gemini://localhost/document.gmi",
    NULL,
};

cli_options_t* parse_options(int argc, const char** argv) {
  cli_options_t* options = calloc(1, sizeof(cli_options_t));
  if (options == NULL) {
    LOG_ERROR("Failed to allocate memory for the CLI options structure");
    return NULL;
  }

  // set default values
  options->gemini_port = 1965;
  options->root = NULL;
  options->chunk_size = DEFAULT_FILE_CHUNK_SIZE;

  const char* root = NULL;
  const char* cert_path = NULL;
  const char* key_path = NULL;
  const char* pre_script_path = NULL;
  const char* post_script_path = NULL;
  const char* error_script_path = NULL;
  const char* script_mode_path = NULL;

  struct argparse_option options_config[] = {
      OPT_HELP(),
      OPT_GROUP("Cryptography"),
      OPT_STRING('c', "cert", &cert_path,
                 "(required) certificate file path (.pem)"),
      OPT_STRING('k', "key", &key_path, "(required) key file path (.pem)"),
      OPT_GROUP("Network"),
      OPT_INTEGER('p', "port", &options->gemini_port,
                  "port to listen for Gemini requests on (default: 1965)"),
      OPT_GROUP("Content"),
      OPT_STRING(
          'r', "root", &root,
          "root directory from which to serve content (default: current)"),
      OPT_INTEGER('u', "chunk", &options->chunk_size,
                  "size in bytes of the chunks loaded into memory while "
                  "serving static files (default: 16384)"),
      OPT_GROUP("Middleware"),
      OPT_STRING('b', "before", &pre_script_path,
                 "script to be run before each request is handled"),
      OPT_STRING('a', "after", &post_script_path,
                 "script to be run after a request has "
                 "resulted in a success response code (20)"),
      OPT_STRING('e', "error", &error_script_path,
                 "script to be run after a request has resulted "
                 "in an error response code (40 thru 59)"),
      OPT_GROUP("Script Mode"),
      OPT_STRING('s', "script", &script_mode_path,
                 "MoonGem will run the provided script and then exit.  Any "
                 "rendered content will be written to stdout.  An additional "
                 "argument may be provided in order to specify the URI to pass "
                 "to the script environment's request data."),
      OPT_END(),
  };

  struct argparse parser;
  argparse_init(&parser, options_config, usage, 0);
  argparse_describe(&parser, "\n" DESCRIPTION, "\n" ADDITIONAL);
  int remaining = argparse_parse(&parser, argc, argv);

  if (script_mode_path != NULL) {
    // run in script mode
    options->script_mode_path = realpath(script_mode_path, NULL);
    if (options->script_mode_path == NULL) {
      LOG_ERROR("Invalid script path");
      goto failure;
    }

    LOG_DEBUG("remaining: %d; argc: %d", remaining, argc);

    if (remaining > 0) {
      options->script_mode_input = strdup(argv[argc - 1]);
    }

    // no other arguments apply in script mode
    return options;
  }

  if (cert_path == NULL) {
    LOG_ERROR("Missing certificate path argument!");
    argparse_usage(&parser);
    goto failure;
  }

  options->cert_path = realpath(cert_path, NULL);
  if (options->cert_path == NULL) {
    LOG_ERROR("Invalid certificate path");
    goto failure;
  }

  if (key_path == NULL) {
    LOG_ERROR("Missing key path argument!");
    argparse_usage(&parser);
    goto failure;
  }

  options->key_path = realpath(key_path, NULL);
  if (options->key_path == NULL) {
    LOG_ERROR("Invalid key path");
    goto failure;
  }

  if (root != NULL) {
    options->root = realpath(root, NULL);
    if (options->root == NULL) {
      LOG_ERROR("Invalid root path");
      goto failure;
    }
  }

  if (pre_script_path != NULL) {
    options->pre_script_path = realpath(pre_script_path, NULL);
    if (options->pre_script_path == NULL) {
      LOG_ERROR("Invalid pre-request script path");
      goto failure;
    }
  }

  if (post_script_path != NULL) {
    options->post_script_path = realpath(post_script_path, NULL);
    if (options->post_script_path == NULL) {
      LOG_ERROR("Invalid post-request script path");
      goto failure;
    }
  }

  if (error_script_path != NULL) {
    options->error_script_path = realpath(error_script_path, NULL);
    if (options->error_script_path == NULL) {
      LOG_ERROR("Invalid error script path");
      goto failure;
    }
  }

  return options;

failure:
  destroy_options(options);
  return NULL;
}

void destroy_options(cli_options_t* options) {
  if (options == NULL) {
    return;
  }

  if (options->root != NULL) {
    free(options->root);
  }

  if (options->cert_path != NULL) {
    free(options->cert_path);
  }

  if (options->key_path != NULL) {
    free(options->key_path);
  }

  if (options->script_mode_path != NULL) {
    free(options->script_mode_path);
  }

  if (options->script_mode_input != NULL) {
    free(options->script_mode_input);
  }

  free(options);
}

#include "options.h"

#include <argparse.h>
#include <stdlib.h>

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
    "moongem [options] -c cert.pem -k key.pem",
    NULL,
};

cli_options_t* parse_options(int argc, const char** argv) {
  cli_options_t* options = malloc(sizeof(cli_options_t));
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
      OPT_END(),
  };

  struct argparse parser;
  argparse_init(&parser, options_config, usage, 0);
  argparse_describe(&parser, "\n" DESCRIPTION, "\n" ADDITIONAL);
  argparse_parse(&parser, argc, argv);

  if (cert_path == NULL) {
    LOG_ERROR("Missing certificate path argument!");
    argparse_usage(&parser);
    goto failure;
  }

  options->cert_path = realpath(cert_path, NULL);
  if (options->cert_path == NULL) {
    perror("Invalid certificate path");
    goto failure;
  }

  if (key_path == NULL) {
    LOG_ERROR("Missing key path argument!");
    argparse_usage(&parser);
    goto failure;
  }

  options->key_path = realpath(key_path, NULL);
  if (options->key_path == NULL) {
    perror("Invalid key path");
    goto failure;
  }

  if (root != NULL) {
    options->root = realpath(root, NULL);
    if (options->root == NULL) {
      perror("Invalid root path");
      return NULL;
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

  free(options);
}

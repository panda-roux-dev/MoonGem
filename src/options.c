#include "options.h"

#include <argparse.h>
#include <stdlib.h>

#include "log.h"

#define USE_IPV6 (1 << 0)
#define USE_IPV4 (1 << 1)
#define USE_BOTH (USE_IPV4 | USE_IPV6)

#define DESCRIPTION                                                   \
  "A Gemini server with inline Lua scripting for generating dynamic " \
  "content"
#define ADDITIONAL                                                   \
  "Developed by panda-roux.  Source and documentation can be found " \
  "at https://sr.ht/~panda-roux/MoonGem"

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
#ifndef DISABLE_HTTP
  options->disable_http = false;
  options->http_port = 8080;
#endif
  options->gemini_port = 1965;
  options->root = NULL;

  int protocol = USE_BOTH;
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
#ifndef DISABLE_HTTP
      OPT_BOOLEAN(0, "no-http", &options->disable_http, "disable HTTP stack"),
      OPT_INTEGER('h', "http-port", &options->http_port,
                  "port to listen for HTTP requests on"),
#endif
      OPT_INTEGER('g', "gemini-port", &options->gemini_port,
                  "port to listen for Gemini requests on"),
      OPT_BIT('4', "ipv4", &protocol, "use IPv4 sockets only", NULL, USE_IPV4,
              OPT_NONEG),
      OPT_BIT('6', "ipv6", &protocol, "use IPv6 sockets only", NULL, USE_IPV6,
              OPT_NONEG),
      OPT_BIT('b', "both", &protocol,
              "use both IPv4 and IPv6 sockets (default)", NULL, USE_BOTH,
              OPT_NONEG),
      OPT_GROUP("Content"),
      OPT_STRING('r', "root", &root, "root from which to serve content"),
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

  options->use_ipv4 = (protocol & USE_IPV4) == USE_IPV4;
  options->use_ipv6 = (protocol & USE_IPV6) == USE_IPV6;

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

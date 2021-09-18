#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdbool.h>

typedef struct cli_options_t {
  int gemini_port;
  int http_port;
  char* root;
  char* cert_path;
  char* key_path;
  bool use_ipv4;
  bool use_ipv6;
  bool disable_http;
} cli_options_t;

cli_options_t* parse_options(int argc, const char** argv);

void destroy_options(cli_options_t* options);

#endif

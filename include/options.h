#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdbool.h>

typedef struct cli_options_t {
  int gemini_port;
  int chunk_size;
  char* root;
  char* cert_path;
  char* key_path;
} cli_options_t;

cli_options_t* parse_options(int argc, const char** argv);

void destroy_options(cli_options_t* options);

#endif

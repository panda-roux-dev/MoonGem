#ifndef HEADER_H
#define HEADER_H

#include <stddef.h>

#define MAX_URL_LENGTH 1024

typedef struct response_t response_t;

size_t extract_input(const char* request, char* input);

int extract_path(char* request, char* buffer, size_t* length);

char* build_tags(response_t* response);

char* build_response_header(int status, char* meta, size_t* length);

#endif

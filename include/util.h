#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "net.h"

#define BUFFER_APPEND_FAILURE INT_MIN

typedef struct {
  size_t length;
  size_t capacity;
  char* buffer;
} text_buffer_t;

text_buffer_t* create_buffer();

int buffer_append(text_buffer_t* buf, char* contents, size_t length);

void destroy_buffer(text_buffer_t* buf);

bool path_is_gmi(const char* path);

bool is_dir(const char* path);

char* append_default_doc(const request_t* request);

bool path_is_illegal(const char* path);

void clear_buffer(text_buffer_t* buf);

int get_env_int(const char* name, int default_value);

size_t response_body_static_file_cb(size_t max, char* buffer, void* data);

void response_static_file_cleanup_cb(void* data);

/*
 * Returns 0 if the operation failed
 */
int check_privileges(void);

size_t read_file(const char* path, char** contents);

/*
 * Returns a string representation of the MIME type of the file at the provided
 * path
 */
char* get_mimetype(const char* path);

#endif

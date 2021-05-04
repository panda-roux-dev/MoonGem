#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <stddef.h>

#define BUFFER_APPEND_FAILURE INT_MIN

typedef struct {
  size_t length;
  size_t capacity;
  char* buffer;
} text_buffer_t;

text_buffer_t* create_buffer();

int buffer_append(text_buffer_t* buf, char* contents, size_t length);

void destroy_buffer(text_buffer_t* buf);

void clear_buffer(text_buffer_t* buf);

/*
 * Returns 0 if the operation failed
 */
int check_privileges(void);

/*
 * Creates a new buffer at `*buffer` and copies the contents of a static file at
 * `path` into it.  The size of the file (in bytes) is stored in `*length`.
 */
void serve_static(char* path, char** buffer, size_t* length);

size_t read_file(const char* path, char** contents);

#endif

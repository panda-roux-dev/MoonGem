#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <net.h>
#include <stddef.h>
#include <stdio.h>

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
callback_result_t serve_static(const char* path, FILE* file,
                               response_t* response);

size_t read_file(const char* path, char** contents);

/*
 * Returns a string representation of the MIME type of the file at the provided
 * path
 */
char* get_mimetype(const char* path);

#endif

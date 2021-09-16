#ifndef BUFFER_H
#define BUFFER_H

#include <stddef.h>

#define BUFFER_APPEND_FAILURE INT_MIN

typedef struct {
  size_t length;
  size_t capacity;
  char* buffer;
} text_buffer_t;

text_buffer_t* create_buffer(void);

int buffer_append(text_buffer_t* buf, char* contents, size_t length);

void destroy_buffer(text_buffer_t* buf);

void clear_buffer(text_buffer_t* buf);

#endif

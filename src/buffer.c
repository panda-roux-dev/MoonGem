#include "buffer.h"

#include <limits.h>
#include <unistd.h>

#include "log.h"

#define BUFFER_DEFAULT_SIZE 1024

text_buffer_t* create_buffer() {
  text_buffer_t* buf = malloc(sizeof(text_buffer_t));
  buf->length = 0;
  buf->capacity = BUFFER_DEFAULT_SIZE;
  buf->buffer = malloc(buf->capacity * sizeof(char));
  return buf;
}

int buffer_append(text_buffer_t* buf, char* contents, size_t length) {
  while (buf->length + length > buf->capacity) {
    buf->capacity *= 2;
    char* temp = realloc(buf->buffer, buf->capacity * sizeof(char));
    if (temp == NULL) {
      LOG_ERROR("Failed to expand text buffer from to %zu bytes in length",
                buf->capacity);
      return BUFFER_APPEND_FAILURE;
    }

    buf->buffer = temp;
  }

  memcpy(&buf->buffer[buf->length], contents, length * sizeof(char));
  buf->length += length;

  return 0;
}

void destroy_buffer(text_buffer_t* buf) {
  if (buf != NULL) {
    if (buf->buffer != NULL) {
      free(buf->buffer);
    }

    free(buf);
  }
}

void clear_buffer(text_buffer_t* buf) {
  memset(buf->buffer, '\0', buf->capacity);
  buf->length = 0;
}


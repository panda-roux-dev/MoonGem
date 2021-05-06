#include "util.h"

#include <magic.h>
#include <status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#define BUFFER_DEFAULT_SIZE 1024
#define FILE_BUFFER_SIZE 2048

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

int check_privileges(void) {
  LOG_DEBUG("Verifying that we aren't running as root...");

  if (getuid() == 0) {
    LOG_ERROR("MoonGem should not be run as root!  Terminating...");
    return 0;
  }

  return 1;
}

size_t read_file(const char* path, char** contents) {
  *contents = NULL;

  if (path == NULL) {
    LOG_ERROR("Cannot read file from empty path");
    return 0;
  }

  // open the file
  FILE* file = fopen(path, "rb");
  if (file == NULL) {
    LOG_ERROR("Failed to open file %s", path);
    return 0;
  }

  // read blocks of size FILE_BUFFER_SIZE into a dynamically-allocated buffer
  size_t bytes_read = 0;
  char buffer[FILE_BUFFER_SIZE];
  char* output = NULL;
  for (;;) {
    size_t n = fread(&buffer[0], sizeof(char), FILE_BUFFER_SIZE, file);
    char* temp = realloc(output, (bytes_read + n) * sizeof(char));
    if (temp == NULL) {
      LOG_ERROR("Failed to expand file buffer to %zu bytes while reading %s",
                (bytes_read + n), path);
      if (output != NULL) {
        free(output);
      }

      fclose(file);
      return 0;
    }

    output = temp;
    memcpy(&output[bytes_read], &buffer[0], n);
    bytes_read += n;
    if (n < FILE_BUFFER_SIZE) {
      break;
    }
  }

  // close the file
  fclose(file);

  {
    // allocate enough space for a null-terminator at the end of the file
    char* temp = realloc(output, (bytes_read + 1) * sizeof(char));
    if (temp == NULL) {
      LOG_ERROR("Failed to allocate space for null-terminator in file %s",
                path);
      free(output);
      return 0;
    }

    output = temp;
  }

  // add null-terminator
  output[bytes_read] = '\0';

  *contents = output;
  return bytes_read;
}

char* get_mimetype(const char* path) {
  struct magic_set* magic = magic_open(MAGIC_MIME | MAGIC_CHECK);
  magic_load(magic, NULL);
  char* result = strdup(magic_file(magic, path));
  magic_close(magic);
  return result;
}

callback_result_t serve_static(const char* path, FILE* file,
                               response_t* response) {
  response->mimetype = get_mimetype(path);
  response->status = STATUS_SUCCESS;

  fseek(file, 0, SEEK_END);
  response->body_length = ftell(file);
  response->body = malloc(response->body_length * sizeof(char));
  if (response->body == NULL) {
    LOG_ERROR("Failed to allocate %zu bytes of memory for %s",
              response->body_length, path);
    response->status = STATUS_PERMANENT_FAILURE;
    response->meta = strdup("File is too large for the server to handle");
    return ERROR;
  }     fseek(file, 0, SEEK_SET);
    fread(response->body, sizeof(char), response->body_length, file);
    return OK;
 
}

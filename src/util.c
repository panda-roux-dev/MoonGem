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
#define DEFAULT_DOCUMENT "index.gmi"
#define EXT_GMI ".gmi"
#define INVALID_URL_PATTERNS "/..", "/.", "/../", "/./", "~/", "$"

int get_env_int(const char* name, int default_value) {
  char* str = getenv(name);
  int value = default_value;
  if (str != NULL) {
    value = (int)atol(str);
    if (value == 0) {
      LOG_ERROR("Invalid value \"%s\" provided for %s", str, name);
      value = default_value;
    }
  }

  return value;
}

bool path_is_gmi(const char* path) {
  if (path == NULL) {
    return false;
  }

  return strcmp(strrchr(path, '.'), EXT_GMI) == 0;
}

bool is_dir(const char* path) { return strrchr(path, '.') == NULL; }

char* append_default_doc(const request_t* request) {
  size_t path_buf_len =
      (request->path_length) + sizeof(DEFAULT_DOCUMENT) / sizeof(char);
  char* path = malloc((path_buf_len + 1) * sizeof(char));
  if (path == NULL) {
    LOG_ERROR("Failed to append default document name to URL");
    return NULL;
  }

  memcpy(path, request->path, request->path_length * sizeof(char));
  if (request->path[request->path_length - 1] != '/') {
    path[request->path_length] = '/';
    memcpy(&path[request->path_length + 1], &DEFAULT_DOCUMENT[0],
           sizeof(DEFAULT_DOCUMENT));
  } else {
    memcpy(&path[request->path_length], &DEFAULT_DOCUMENT[0],
           sizeof(DEFAULT_DOCUMENT));
  }

  path[path_buf_len] = '\0';

  return path;
}

bool path_is_illegal(const char* path) {
  const char* bad_strings[] = {INVALID_URL_PATTERNS};
  for (int i = 0; i < sizeof(bad_strings) / sizeof(char*); ++i) {
    if (strstr(path, bad_strings[i]) != NULL) {
      return true;
    }
  }

  return false;
}

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

size_t response_body_static_file_cb(size_t max, char* buffer, void* data) {
  if (data == NULL) {
    return 0;
  }

  return fread(buffer, sizeof(char), max, (FILE*)data);
}

void response_static_file_cleanup_cb(void* data) {
  if (data != NULL) {
    fclose((FILE*)data);
  }
}


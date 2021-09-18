#include "util.h"

#include <magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "net.h"

#define FILE_BUFFER_SIZE 2048

bool is_dir(const char* path) { return strrchr(path, '.') == NULL; }

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

int check_privileges(void) {
  if (getuid() == 0) {
    LOG_ERROR("MoonGem should not be run as root!  Terminating...");
    return 0;
  }

  return 1;
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

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>

#define CHECK_FREE(obj) \
  if ((obj) != NULL) free((obj));

int get_env_int(const char* name, int default_value);

typedef struct file_info_t {
  FILE* ptr;
  size_t offset;
  off_t size;
  int fd;
} file_info_t;

#endif

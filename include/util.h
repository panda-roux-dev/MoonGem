#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>

#define CHECK_FREE(obj) \
  if ((obj) != NULL) free((obj));

int get_env_int(const char* name, int default_value);

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

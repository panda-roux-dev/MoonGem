#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>

typedef struct request_t request_t;

bool is_dir(const char* path);

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

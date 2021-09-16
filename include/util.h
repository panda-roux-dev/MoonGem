#ifndef UTIL_H
#define UTIL_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#define BUFFER_APPEND_FAILURE INT_MIN

typedef struct request_t request_t;

typedef struct {
  size_t length;
  size_t capacity;
  char* buffer;
} text_buffer_t;

bool should_terminate(void);

bool is_stopped(void);

void install_signal_handler(void);

void wait_until_continue(void);

text_buffer_t* create_buffer(void);

int buffer_append(text_buffer_t* buf, char* contents, size_t length);

void destroy_buffer(text_buffer_t* buf);

void clear_buffer(text_buffer_t* buf);

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

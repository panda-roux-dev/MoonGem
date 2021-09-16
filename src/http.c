#include "http.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RESPONSE_STATUS_LINE_MAX_LENGTH 256

int write_status_code_response(int fd, int status, const char* message) {
  char buffer[RESPONSE_STATUS_LINE_MAX_LENGTH];
  memset(&buffer[0], 0, sizeof(buffer) / sizeof(char));
  size_t length = snprintf(&buffer[0], RESPONSE_STATUS_LINE_MAX_LENGTH,
                           "HTTP/1.1 %d %s\r\n", status, message);
  write(fd, &buffer[0], length);
  return length;
}


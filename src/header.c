#include "header.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gemini.h"
#include "log.h"

#define MAX_META_LENGTH 1024
#define HEADER_BUFFER_LENGTH 1029  // code(2) + space(1) + meta(1024) + \r\n

#define URL_SCHEME "gemini://"
#define URL_TERMINATOR "\r\n"
#define URL_INPUT_DELIMITER '?'
#define URL_PATH_DELIMITER '/'

#define EXTRACT_PATH_FAILURE INT_MIN

size_t extract_input(const char* request, char* input) {
  char* term = strstr(request, URL_TERMINATOR);
  if (term == NULL) {
    return 0;
  }

  char* input_delim = memchr(request, URL_INPUT_DELIMITER, term - request);
  if (input_delim == NULL) {
    return 0;
  }

  ++input_delim;  // skip delimiter

  size_t input_len = term - input_delim;
  memcpy(input, input_delim, input_len * sizeof(char));
  input[input_len] = '\0';

  return input_len;
}

// TODO: use regex for this like a sane person
int extract_path(char* request, char* buffer, size_t* length) {
  // first check that the request body begins with the URL scheme
  if (strstr(request, URL_SCHEME) != request) {
    return EXTRACT_PATH_FAILURE;
  }

  // host starts after the scheme
  char* host_begin = &request[sizeof(URL_SCHEME) / sizeof(char)];

  // ensure that there's a \r\n terminating the request
  char* term = strstr(request, URL_TERMINATOR);
  if (term == NULL || term == host_begin) {
    return EXTRACT_PATH_FAILURE;
  }

  // check for input after the path
  char* input_delim =
      memchr(host_begin, URL_INPUT_DELIMITER, term - host_begin);

  // path (if one exists) is everything between the first forward-slash after
  // the host and either the "?" input delimiter or the \r\n terminator

  char* path = memchr(host_begin, '/', term - host_begin);

  size_t len = input_delim == NULL || input_delim > term ? term - path
                                                         : input_delim - path;

  // check if a path exists; if so, copy it into the buffer.
  //
  // otherwise, set length to zero and set up the buffer as an empty string
  if (path != NULL) {
    memcpy(buffer, path, len);
    buffer[len] = '\0';
  } else {
    len = 0;
    buffer[0] = '\0';
  }

  *length = len;
  return 0;
}

char* build_tags(response_t* response) {
  char* buffer = malloc(MAX_META_LENGTH * sizeof(char));
  memset(buffer, '\0', MAX_META_LENGTH);

  if (buffer == NULL) {
    LOG_ERROR("Failed to allocate response header tags buffer");
    return NULL;
  }

  // write meta field
  int tags_written = 0;
  int offset = 0;
  if (response->meta != NULL) {
    offset += snprintf(buffer, MAX_META_LENGTH, "%s", response->meta);
    ++tags_written;
  }

  // write mimetype
  if (response->mimetype != NULL) {
    if (tags_written > 0) {
      offset += snprintf(buffer, MAX_META_LENGTH - offset, "; %s",
                         response->mimetype);
    } else {
      offset += snprintf(buffer, MAX_META_LENGTH, "%s", response->mimetype);
    }
    ++tags_written;
  }

  // write language
  if (response->language != NULL) {
    if (tags_written > 0) {
      snprintf(buffer, MAX_META_LENGTH - offset, "; lang=%s",
               response->language);
    } else {
      snprintf(buffer, MAX_META_LENGTH, "lang=%s", response->language);
    }
  }

  return buffer;
}

char* build_response_header(int status, char* meta, size_t* length) {
  // set up an initial buffer with enough space to store the header
  char header[HEADER_BUFFER_LENGTH];
  memset(&header[0], '\0', HEADER_BUFFER_LENGTH);

  // check size of the meta field, if it's set;
  //
  // - if meta is set, then validate its length and write it into the header
  // - otherwise if meta is not set, write a header without it
  size_t header_len = 0;
  if (meta != NULL) {
    header_len =
        snprintf(&header[0], HEADER_BUFFER_LENGTH, "%d %s\r\n", status, meta);
  } else {
    header_len = snprintf(&header[0], HEADER_BUFFER_LENGTH, "%d\r\n", status);
  }

  if (header_len >= HEADER_BUFFER_LENGTH || header_len <= 0) {
    LOG_ERROR("Failed to generate a response header");
    return NULL;
  }

  *length = header_len;

  // return a copy of the header in a heap-allocated buffer
  char* copy = strndup(&header[0], header_len);
  if (copy == NULL) {
    LOG_ERROR("Failed to allocate header buffer");
  }

  return copy;
}

#include "uri.h"

#include <pcre2posix.h>
#include <string.h>

#include "log.h"
#include "util.h"

#define DEFAULT_DOCUMENT "index.gmi"
#define EXT_GMI ".gmi"
#define ILLEGAL_PATH_SEQUENCES "..", "~", "$", "*"

#define URI_PATTERN                                        \
  "(?:(?:([a-z]+):\\/\\/"                                  \
  ")?([a-z0-9]{1}[a-z0-9.\\-]+)(?::([0-9]{2,5}))?)?(?:\\/" \
  "([^\\r\\n\\?]*[^\\r\\n\\?\\/])\\/?)?(?:(?:\\/)?\\?([^\\r\\n\\?]+))?"

#define URI_PART_COUNT 6
#define URI_SCHEME 1
#define URI_HOST 2
#define URI_PORT 3
#define URI_PATH 4
#define URI_INPUT 5

static regex_t uri_regexp;
static char regex_error[512] = {0};

static bool path_is_gmi(const char* path) {
  if (path == NULL) {
    return false;
  }

  return strcmp(strrchr(path, '.'), EXT_GMI) == 0;
}

static bool path_is_illegal(const char* path) {
  const char* bad_strings[] = {ILLEGAL_PATH_SEQUENCES};
  for (int i = 0; i < sizeof(bad_strings) / sizeof(char*); ++i) {
    if (strstr(path, bad_strings[i]) != NULL) {
      return true;
    }
  }

  return false;
}

static char* extract_part(regmatch_t* match, const char* buf) {
  regoff_t start = match->rm_so;
  regoff_t end = match->rm_eo;
  return start < 0 || start == end ? NULL : strndup(&buf[start], end - start);
}

static void standardize_path(char** path) {
  // if empty path, append default document
  if (*path == NULL) {
    LOG_DEBUG("Empty path; appending default document");
    *path = strdup(DEFAULT_DOCUMENT);
    return;
  }

  size_t initial_len = strnlen(*path, URI_PATH_MAX);

  // if path ends in forward-slash or looks like a directory, grow and append
  // default document
  char* last_delim = strrchr(*path, '/');
  char* last_period = strrchr(*path, '.');
  if ((*path)[initial_len - 1] == '/' || last_period == NULL ||
      last_delim > last_period) {
    LOG_DEBUG("Path looks like a directory; appending default document");

    size_t new_len = initial_len + sizeof(DEFAULT_DOCUMENT) + 1;

    char* tmp = realloc(*path, new_len);
    if (tmp == NULL) {
      LOG_ERROR(
          "Failed to reallocate enough space to append default document onto "
          "the request path");
      free(*path);
      *path = NULL;
      return;
    }

    *path = tmp;
    strncat(&(*path)[initial_len], "/" DEFAULT_DOCUMENT,
            sizeof(DEFAULT_DOCUMENT) + 1);
  } else {
    LOG_DEBUG("Path looks like a file; leaving it as-is");
  }
}

int init_uri_regex(void) {
  int status = regcomp(&uri_regexp, URI_PATTERN, REG_ICASE);

  LOG_DEBUG("URI pattern: %s", URI_PATTERN);

  if (status != 0) {
    regerror(status, &uri_regexp, &regex_error[0], sizeof(regex_error));
    LOG_ERROR("Failed to compile URI regex: %s", &regex_error[0]);
    return -1;
  }

  return 0;
}

void cleanup_uri_regex(void) { regfree(&uri_regexp); }

uri_t* create_uri(const char* buf) {
  if (buf == NULL) {
    LOG_DEBUG("Empty URI buffer");
    return NULL;
  }

  regmatch_t matches[URI_PART_COUNT] = {0};
  switch (regexec(&uri_regexp, buf, URI_PART_COUNT, &matches[0],
                  REG_NOTBOL | REG_NOTEOL)) {
    case REG_ESPACE:
    case REG_NOMATCH:
      return NULL;
    default:
      break;
  }

  LOG_DEBUG("Request: %s", buf);

  uri_t* uri = malloc(sizeof(uri_t));
  uri->scheme = extract_part(&matches[URI_SCHEME], buf);
  uri->host = extract_part(&matches[URI_HOST], buf);
  uri->port = extract_part(&matches[URI_PORT], buf);
  uri->raw_path = extract_part(&matches[URI_PATH], buf);
  uri->input = extract_part(&matches[URI_INPUT], buf);

  if (uri->raw_path != NULL) {
    uri->path = strdup(uri->raw_path);
  }

  standardize_path(&uri->path);

  // path can be null if EOM occurred trying to add default doc
  if (uri->path == NULL || path_is_illegal(uri->path)) {
    destroy_uri(uri);
    return NULL;
  }

  uri->type = path_is_gmi(uri->path) ? URI_TYPE_GEMTEXT : URI_TYPE_FILE;

  LOG_DEBUG("Scheme: %s", uri->scheme);
  LOG_DEBUG("Host:   %s", uri->host);
  LOG_DEBUG("Port:   %s", uri->port);
  LOG_DEBUG("Path:   %s", uri->path);
  LOG_DEBUG("Input:  %s", uri->input);

  return uri;
}

void destroy_uri(uri_t* uri) {
  if (uri == NULL) {
    return;
  }

  CHECK_FREE(uri->scheme);
  CHECK_FREE(uri->host);
  CHECK_FREE(uri->port);
  CHECK_FREE(uri->path);
  CHECK_FREE(uri->input);
  CHECK_FREE(uri->raw_path);

  free(uri);
}

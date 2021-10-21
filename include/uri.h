#ifndef URI_H
#define URI_H

typedef enum uri_type_t { URI_TYPE_GEMTEXT, URI_TYPE_FILE } uri_type_t;

typedef struct uri_t {
  char* scheme;
  char* host;
  char* port;
  char* path;
  char* input;
  uri_type_t type;
} uri_t;

/*
 * Compiles the URI-parsing regex, returns 0 on success
 */
int init_uri_regex(void);

/*
 * Frees the URI-parsing regex
 */
void cleanup_uri_regex(void);

uri_t* create_uri(const char* buf);

void destroy_uri(uri_t* uri);

#endif

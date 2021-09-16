#define _GNU_SOURCE

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "gemini.h"
#include "handler.h"
#include "log.h"
#include "util.h"

#define THREAD_NAME_GEMINI "listener-gemini"
#define THREAD_NAME_HTTP "listener-http"

#define DEFAULT_GEMINI_PORT 1965
#define DEFAULT_HTTP_PORT 8080

#define VAR_GEMINI_PORT "MOONGEM_GEMINI_PORT"
#define VAR_HTTP_PORT "MOONGEM_HTTP_PORT"

typedef struct cli_options_t {
  char* cert_path;
  char* key_path;
} cli_options_t;

void* listen_for_gemini_requests(void* ptr) {
  int port = get_env_int(VAR_GEMINI_PORT, DEFAULT_GEMINI_PORT);
  cli_options_t* options = (cli_options_t*)ptr;

  // set up socket + TLS
  net_t* sock;
  if ((sock = init_tls_socket(port, options->cert_path, options->key_path)) ==
      NULL) {
    LOG_ERROR("Failed to initialize socket for Gemini listener");
  } else {
    // begin listening for requests
    LOG("Listening for Gemini requests on port %d...", port);
    handle_gemini_requests(sock);
    destroy_socket(sock);
  }

  return NULL;
}

int main(int argc, const char** argv) {
  if (argc < 3) {
    LOG_ERROR(
        "Missing arguments!  Usage: moongem <cert-path> <key-path> [path]");
    return EXIT_FAILURE;
  }

  cli_options_t options = {realpath(argv[1], NULL), realpath(argv[2], NULL)};

  if (!check_privileges()) {
    // don't run if we can't drop privileges
    return EXIT_FAILURE;
  }

  // move the working directory to the path in the third argument, if present
  if (argc >= 4) {
    char* cwd = realpath(argv[3], NULL);
    chdir(cwd);
  }

  // handle SIGPIPE events
  install_signal_handler();

  pthread_t gemini_thread;
  pthread_create(&gemini_thread, NULL, listen_for_gemini_requests, &options);
  pthread_setname_np(gemini_thread, THREAD_NAME_GEMINI);

  pthread_join(gemini_thread, NULL);

  free(options.cert_path);
  free(options.key_path);

  return EXIT_SUCCESS;
}

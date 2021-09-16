#include "util.h"

#include <magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "net.h"

#define FILE_BUFFER_SIZE 2048

static volatile sig_atomic_t terminate = 0;
static volatile sig_atomic_t stop = 0;

static void sig_terminate_handler(int sig) { terminate = 1; }

static void sig_stop_handler(int sig) { stop = 1; }

static void sig_kill_handler(int _) { exit(EXIT_FAILURE); }

bool should_terminate(void) { return terminate; }

bool is_stopped(void) { return stop; }

void install_signal_handler(void) {
  signal(SIGKILL, sig_kill_handler);
  signal(SIGTERM, sig_terminate_handler);
  signal(SIGABRT, sig_terminate_handler);
  signal(SIGINT, sig_terminate_handler);
  signal(SIGSTOP, sig_stop_handler);
  signal(SIGTSTP, sig_stop_handler);
}

void wait_until_continue(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGCONT);
  sigaddset(&set, SIGKILL);
  sigaddset(&set, SIGABRT);
  sigaddset(&set, SIGINT);

  int sig;
  sigwait(&set, &sig);

  stop = 0;
  if (sig != SIGCONT) {
    if (sig != SIGKILL) {
      terminate = 1;
    } else {
      exit(EXIT_FAILURE);
    }
  }
}

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

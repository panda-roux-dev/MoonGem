#include "util.h"

#include <stdlib.h>

#include "log.h"

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

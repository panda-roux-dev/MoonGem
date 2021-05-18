#ifndef LOG_H
#define LOG_H

#ifndef MOONGEM_DISABLE_LOGGING

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)                       \
  {                                               \
    if (errno > 0) {                              \
      fprintf(stderr, fmt, ##__VA_ARGS__);        \
      fprintf(stderr, ": %s\n", strerror(errno)); \
    } else {                                      \
      fprintf(stderr, fmt "\n", ##__VA_ARGS__);   \
    }                                             \
  }

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) \
  printf("DEBUG: [%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) (void)(fmt)
#endif

#else

#define LOG(fmt, ...) (void)(fmt)
#define LOG_ERROR(fmt, ...) (void)(fmt)
#define LOG_DEBUG(fmt, ...) (void)(fmt)

#endif

#endif

#ifndef RUNTIME_H
#define RUNTIME_H

#include <stdbool.h>

bool should_terminate(void);

bool is_stopped(void);

void begin_signal_handler(void);

#endif

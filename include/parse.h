#ifndef PARSE_H
#define PARSE_H

#include <limits.h>
#include <stdio.h>

#include "net.h"

int parse_response_from_file(FILE* file, const request_t* request,
                             response_t* response);

#endif

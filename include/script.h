#ifndef SCRIPT_H
#define SCRIPT_H

#include "net.h"

#define FLD_PATH "PATH"

#define FLD_INPUT "_INPUT"

#define TBL_RESPONSE "_RESPONSE"
#define FLD_BUFFER "buffer"
#define FLD_RESPONSE_PTR "ptr"

#define RUN_SCRIPT_FAILURE INT_MIN

typedef struct lua_State lua_State;

typedef struct {
  size_t result_len;
  lua_State* L;
  char* language;
  char* result;
} script_ctx_t;

script_ctx_t* init_script(const request_t* request, response_t* response);

void destroy_script(script_ctx_t* ctx);

int run_script(script_ctx_t* ctx, char* contents);

#endif

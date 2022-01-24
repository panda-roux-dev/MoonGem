#ifndef SCRIPT_H
#define SCRIPT_H

#include <event2/buffer.h>
#include <stddef.h>

#include "gemini.h"

// the following are stored in the registry table:
#define FLD_RESPONSE "__RESPONSE"
#define FLD_REQUEST "__REQUEST"
#define FLD_BUFFER "__BUFFER"
#define FLD_INPUT "__INPUT"

typedef struct script_ctx_t script_ctx_t;

typedef enum script_result_t { SCRIPT_OK, SCRIPT_ERROR } script_result_t;

script_ctx_t* create_script_ctx(gemini_context_t* gemini);

void destroy_script(script_ctx_t* ctx);

script_result_t exec_script(script_ctx_t* ctx, char* script, size_t script_len,
                            struct evbuffer* output);

script_result_t exec_script_file(script_ctx_t* ctx, const char* path,
                                 struct evbuffer* output);

#endif

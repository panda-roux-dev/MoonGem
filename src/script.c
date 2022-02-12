#include "script.h"

#include <lauxlib.h>
#include <libgen.h>
#include <lua.h>
#include <lualib.h>
#include <stdlib.h>
#include <string.h>

#include "gemini.h"
#include "log.h"
#include "status.h"
#include "uri.h"

#define LIBRARY_TABLE_NAME "mg"

#define FUNC_SET_PATH "set_path"
#define FUNC_INTERRUPT "interrupt"

#define FUNC_INPUT "get_input"
#define FUNC_INPUT_SENSITIVE "get_sensitive_input"
#define FUNC_HAS_INPUT "has_input"
#define FUNC_GET_PATH "get_path"

#define FUNC_CERT "get_cert"
#define FUNC_HAS_CERT "has_cert"

#define FUNC_LANG "set_language"
#define FUNC_SUCCESS "success"
#define FUNC_TEMP_REDIRECT "temp_redirect"
#define FUNC_REDIRECT "redirect"
#define FUNC_TEMP_FAILURE "temp_failure"
#define FUNC_UNAVAILABLE "unavailable"
#define FUNC_CGI_ERROR "cgi_error"
#define FUNC_PROXY_ERROR "proxy_error"
#define FUNC_SLOW_DOWN "slow_down"
#define FUNC_FAILURE "failure"
#define FUNC_NOT_FOUND "not_found"
#define FUNC_GONE "gone"
#define FUNC_PROXY_REFUSED "proxy_refused"
#define FUNC_BAD_REQUEST "bad_request"
#define FUNC_CERT_REQUIRED "cert_required"
#define FUNC_CERT_UNAUTHORIZED "unauthorized"

#define FUNC_INCLUDE "include"
#define FUNC_WRITE "write"
#define FUNC_LINE "line"
#define FUNC_LINK "link"
#define FUNC_HEADING "head"
#define FUNC_QUOTE "quote"
#define FUNC_BLOCK "block"
#define FUNC_BEGIN_BLOCK "begin_block"
#define FUNC_END_BLOCK "end_block"

#define SCRIPT_BUFFER_SIZE (1 << 16)

static char global_script_buffer[SCRIPT_BUFFER_SIZE];

typedef struct script_ctx_t {
  lua_State* L;
  const request_t* request;
  response_t* response;
} script_ctx_t;

/* Pre-Request */
int api_set_path(lua_State* L);
int api_interrupt(lua_State* L);

/* Input */
int api_get_input(lua_State* L);
int api_get_input_sensitive(lua_State* L);
int api_has_input(lua_State* L);
int api_get_path(lua_State* L);

/* Certificates */
int api_get_cert(lua_State* L);
int api_has_cert(lua_State* L);

/* Response */
int api_set_lang(lua_State* L);
int api_success(lua_State* L);
int api_temp_redirect(lua_State* L);
int api_perm_redirect(lua_State* L);
int api_temp_failure(lua_State* L);
int api_unavailable(lua_State* L);
int api_cgi_error(lua_State* L);
int api_proxy_error(lua_State* L);
int api_slow_down(lua_State* L);
int api_perm_failure(lua_State* L);
int api_not_found(lua_State* L);
int api_gone(lua_State* L);
int api_proxy_refused(lua_State* L);
int api_bad_request(lua_State* L);
int api_cert_required(lua_State* L);
int api_cert_unauthorized(lua_State* L);

/* Body */
int api_include(lua_State* L);
int api_write(lua_State* L);
int api_line(lua_State* L);
int api_link(lua_State* L);
int api_heading(lua_State* L);
int api_quote(lua_State* L);
int api_block(lua_State* L);
int api_beginblock(lua_State* L);
int api_endblock(lua_State* L);

static void set_api_methods(lua_State* L) {
  luaL_Reg methods[] = {{FUNC_SET_PATH, api_set_path},
                        {FUNC_INTERRUPT, api_interrupt},

                        {FUNC_INPUT, api_get_input},
                        {FUNC_INPUT_SENSITIVE, api_get_input_sensitive},
                        {FUNC_HAS_INPUT, api_has_input},
                        {FUNC_GET_PATH, api_get_path},

                        {FUNC_CERT, api_get_cert},
                        {FUNC_HAS_CERT, api_has_cert},

                        {FUNC_LANG, api_set_lang},
                        {FUNC_REDIRECT, api_perm_redirect},
                        {FUNC_SUCCESS, api_success},
                        {FUNC_TEMP_REDIRECT, api_temp_redirect},
                        {FUNC_TEMP_FAILURE, api_temp_failure},
                        {FUNC_UNAVAILABLE, api_unavailable},
                        {FUNC_CGI_ERROR, api_cgi_error},
                        {FUNC_PROXY_ERROR, api_proxy_error},
                        {FUNC_SLOW_DOWN, api_slow_down},
                        {FUNC_FAILURE, api_perm_failure},
                        {FUNC_NOT_FOUND, api_not_found},
                        {FUNC_GONE, api_gone},
                        {FUNC_PROXY_REFUSED, api_proxy_refused},
                        {FUNC_BAD_REQUEST, api_bad_request},
                        {FUNC_CERT_REQUIRED, api_cert_required},
                        {FUNC_CERT_UNAUTHORIZED, api_cert_unauthorized},

                        {FUNC_INCLUDE, api_include},
                        {FUNC_WRITE, api_write},
                        {FUNC_LINE, api_line},
                        {FUNC_LINK, api_link},
                        {FUNC_HEADING, api_heading},
                        {FUNC_QUOTE, api_quote},
                        {FUNC_BLOCK, api_block},
                        {FUNC_BEGIN_BLOCK, api_beginblock},
                        {FUNC_END_BLOCK, api_endblock},

                        {NULL, NULL}};

  luaL_newlib(L, methods);
  lua_setglobal(L, LIBRARY_TABLE_NAME);
}

static void set_registry_data(script_ctx_t* ctx) {
  lua_State* L = ctx->L;
  response_t* response = ctx->response;
  const request_t* request = ctx->request;

  lua_pushlightuserdata(L, response);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);

  lua_pushlightuserdata(L, (request_t*)request);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);

  // add user input as a global variable, if present
  if (request->uri->input != NULL) {
    lua_pushstring(L, request->uri->input);
    lua_setfield(L, LUA_REGISTRYINDEX, FLD_INPUT);
  }
}

static void set_response_buffer(lua_State* L, struct evbuffer* buffer) {
  lua_pushlightuserdata(L, (void*)buffer);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
}

static void append_package_path(script_ctx_t* ctx) {
  lua_State* L = ctx->L;
  const char* path = ctx->request->uri->path;

  if (path == NULL) {
    return;
  }

  /*
  // skip the first forward-slash
  ++path;
  */

  // add the request path to package.path
  lua_getglobal(L, "package");
  lua_getfield(L, -1, "path");
  if (strrchr(path, '.') != NULL) {
    char* path_copy = strdup(path);
    char* dir = dirname(path_copy);
    lua_pushfstring(L, ";./%s/?.lua", dir);
    lua_pushfstring(L, ";./%s/?", dir);
    free(dir);
  } else {
    lua_pushfstring(L, ";./%s/?.lua", path);
    lua_pushfstring(L, ";./%s/?", path);
  }

  lua_concat(L, 3);
  lua_setfield(L, -2, "path");
}

script_ctx_t* create_script_ctx(gemini_context_t* gemini) {
  script_ctx_t* ctx = calloc(1, sizeof(script_ctx_t));
  if (ctx == NULL) {
    LOG_ERROR("Failed to allocate space for the script context");
    return NULL;
  }

  lua_State* L = luaL_newstate();
  luaL_openlibs(L);

  ctx->L = L;
  ctx->request = &gemini->request;
  ctx->response = &gemini->response;

  append_package_path(ctx);
  set_registry_data(ctx);
  set_api_methods(L);

  return ctx;
}

void destroy_script(script_ctx_t* ctx) {
  if (ctx != NULL) {
    if (ctx->L != NULL) {
      lua_close(ctx->L);
    }

    free(ctx);
  }
}

script_result_t exec_script(script_ctx_t* ctx, char* script, size_t script_len,
                            struct evbuffer* output) {
  if (script_len >= SCRIPT_BUFFER_SIZE) {
    LOG_ERROR(
        "Refusing to execute a script that is greater than the maximum length "
        "of %d bytes!",
        SCRIPT_BUFFER_SIZE - 1);
    return SCRIPT_ERROR;
  }

  lua_State* L = ctx->L;

  set_response_buffer(L, output);

  // we have to copy the script body to a buffer so that we can null-terminate
  // it, as the Lua API doesn't provide a way to run a string with an explicit
  // length
  memcpy(&global_script_buffer[0], script, script_len);
  global_script_buffer[script_len] = '\0';

  lua_pop(L, lua_gettop(L));
  if (luaL_dostring(L, &global_script_buffer[0]) != LUA_OK) {
    if (lua_isstring(L, -1)) {
      LOG_ERROR("Error running script: %s", lua_tostring(L, -1));
    } else {
      LOG_ERROR("Error running script");
    }

    return SCRIPT_ERROR;
  }

  LOG_DEBUG("Ran a script of length %zu", script_len);

  // if the script returned a string, write it to the buffer because that's
  // nice
  if (lua_gettop(L) > 0 && lua_isstring(L, -1)) {
    const char* text = lua_tostring(L, -1);
    evbuffer_add_printf(output, "%s", text);
  }

  return SCRIPT_OK;
}

script_result_t exec_script_file(script_ctx_t* ctx, const char* path,
                                 struct evbuffer* output) {
  lua_State* L = ctx->L;

  set_response_buffer(L, output);

  if (luaL_dofile(ctx->L, path) != LUA_OK) {
    if (lua_isstring(L, -1)) {
      LOG_ERROR("Error running script file at %s: %s", path,
                lua_tostring(L, -1));
    } else {
      LOG_ERROR("Error running script file at %s", path);
    }

    return SCRIPT_ERROR;
  }

  LOG_DEBUG("Ran script at %s", path);

  return SCRIPT_OK;
}

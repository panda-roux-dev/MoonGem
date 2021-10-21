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

#define LIBRARY_TABLE_NAME "mg"

#define FUNC_INCLUDE "include"
#define FUNC_WRITE "write"
#define FUNC_LINE "line"
#define FUNC_LINK "link"
#define FUNC_HEADING "heading"
#define FUNC_QUOTE "quote"
#define FUNC_BLOCK "block"
#define FUNC_BEGIN_BLOCK "begin_block"
#define FUNC_END_BLOCK "end_block"

#define FUNC_LANG "set_lang"
#define FUNC_INPUT "get_input"
#define FUNC_INPUT_SENSITIVE "get_sensitive_input"
#define FUNC_CERT "get_cert"
#define FUNC_CHECKCERT "has_cert"
#define FUNC_REDIRECT "redirect"
#define FUNC_TEMP_REDIRECT "temp_redirect"
#define FUNC_PERM_REDIRECT "perm_redirect"

typedef struct script_ctx_t {
  lua_State* L;
  const request_t* request;
  response_t* response;
} script_ctx_t;

/*
 * Forward-declare methods defined in api.c
 */
int api_head_set_lang(lua_State* L);

int api_head_get_input(lua_State* L);

int api_head_get_input_sensitive(lua_State* L);

int api_head_get_cert(lua_State* L);

int api_head_has_cert(lua_State* L);

int api_head_temp_redirect(lua_State* L);

int api_head_perm_redirect(lua_State* L);

int api_body_include(lua_State* L);

int api_body_write(lua_State* L);

int api_body_line(lua_State* L);

int api_body_link(lua_State* L);

int api_body_heading(lua_State* L);

int api_body_quote(lua_State* L);

int api_body_block(lua_State* L);

int api_body_beginblock(lua_State* L);

int api_body_endblock(lua_State* L);

static void set_api_methods(lua_State* L) {
  luaL_Reg methods[] = {{FUNC_INCLUDE, api_body_include},
                        {FUNC_WRITE, api_body_write},
                        {FUNC_LINE, api_body_line},
                        {FUNC_LINK, api_body_link},
                        {FUNC_HEADING, api_body_heading},
                        {FUNC_QUOTE, api_body_quote},
                        {FUNC_BLOCK, api_body_block},
                        {FUNC_BEGIN_BLOCK, api_body_beginblock},
                        {FUNC_END_BLOCK, api_body_endblock},
                        {FUNC_LANG, api_head_set_lang},
                        {FUNC_INPUT, api_head_get_input},
                        {FUNC_INPUT_SENSITIVE, api_head_get_input_sensitive},
                        {FUNC_CERT, api_head_get_cert},
                        {FUNC_CHECKCERT, api_head_has_cert},
                        {FUNC_REDIRECT, api_head_temp_redirect},
                        {FUNC_TEMP_REDIRECT, api_head_temp_redirect},
                        {FUNC_PERM_REDIRECT, api_head_perm_redirect},
                        {NULL, NULL}};

  luaL_newlib(L, methods);
  lua_setglobal(L, LIBRARY_TABLE_NAME);
}

static void set_script_globals(script_ctx_t* ctx) {
  lua_State* L = ctx->L;
  response_t* response = ctx->response;
  const request_t* request = ctx->request;

  lua_pushlightuserdata(L, response);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);

  lua_pushlightuserdata(L, (request_t*)request);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);

  lua_pushinteger(L, 0);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_SIZE);

  // set the PATH global variable
  lua_pushstring(L, request->uri->path);
  lua_setglobal(L, FLD_PATH);

  // add user input as a global variable, if present
  if (request->uri->input != NULL) {
    lua_pushstring(L, request->uri->input);
    lua_setglobal(L, FLD_INPUT);
  }
}

static void set_response_buffer(lua_State* L, struct evbuffer* buffer) {
  lua_pushlightuserdata(L, (void*)buffer);
  lua_setfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
}

static void add_package_path(script_ctx_t* ctx) {
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
    char* dir = dirname((char*)path);
    lua_pushfstring(L, ";./%s/?.lua", dir);
    lua_pushfstring(L, ";./%s/?", dir);
  } else {
    lua_pushfstring(L, ";./%s/?.lua", path);
    lua_pushfstring(L, ";./%s/?", path);
  }

  lua_concat(L, 3);
  lua_setfield(L, -2, "path");
}

script_ctx_t* create_script_ctx(const request_t* request,
                                response_t* response) {
  script_ctx_t* ctx = calloc(1, sizeof(script_ctx_t));
  if (ctx == NULL) {
    LOG_ERROR("Failed to allocate space for the script context");
    return NULL;
  }

  lua_State* L = luaL_newstate();

  ctx->L = L;
  ctx->request = request;
  ctx->response = response;

  luaL_openlibs(L);
  add_package_path(ctx);
  set_script_globals(ctx);
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
  lua_State* L = ctx->L;

  set_response_buffer(L, output);

  script = strndup(script, script_len);

  LOG_DEBUG("Script: %s", script);

  script_result_t result = SCRIPT_OK;
  if (luaL_dostring(L, script) != LUA_OK) {
    LOG_ERROR("Error running Lua script: %s", lua_tostring(L, -1));
    result = SCRIPT_ERROR;
  }

  // at this point, any resulting text produced by the script is contained in
  // the results buffer

  free(script);

  return result;
}

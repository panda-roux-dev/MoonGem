#include "script.h"

#include <lauxlib.h>
#include <libgen.h>
#include <lua.h>
#include <lualib.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "status.h"

#define TBL_HEADER "HEAD"
#define FUNC_LANG "set_lang"
#define FUNC_INPUT "get_input"
#define FUNC_INPUT_SENSITIVE "get_sensitive_input"
#define FUNC_CERT "get_cert"
#define FUNC_CHECKCERT "has_cert"

#define TBL_BODY "BODY"
#define FUNC_INCLUDE "include"
#define FUNC_WRITE "write"
#define FUNC_LINE "line"
#define FUNC_LINK "link"
#define FUNC_HEADING "heading"
#define FUNC_QUOTE "quote"
#define FUNC_BLOCK "block"
#define FUNC_BEGIN_BLOCK "begin_block"
#define FUNC_END_BLOCK "end_block"

/*
 * Forward-declare methods defined in api.c
 */
int api_head_set_lang(lua_State* L);

int api_head_get_input(lua_State* L);

int api_head_get_input_sensitive(lua_State* L);

int api_head_get_cert(lua_State* L);

int api_head_has_cert(lua_State* L);

int api_body_include(lua_State* L);

int api_body_write(lua_State* L);

int api_body_line(lua_State* L);

int api_body_link(lua_State* L);

int api_body_heading(lua_State* L);

int api_body_quote(lua_State* L);

int api_body_block(lua_State* L);

int api_body_beginblock(lua_State* L);

int api_body_endblock(lua_State* L);

static void add_body_api_methods(lua_State* L) {
  lua_newtable(L);

  lua_getglobal(L, TBL_RESPONSE);
  lua_setfield(L, -2, TBL_RESPONSE);

  lua_pushcfunction(L, api_body_include);
  lua_setfield(L, -2, FUNC_INCLUDE);

  lua_pushcfunction(L, api_body_include);
  lua_setfield(L, -2, FUNC_INCLUDE);

  lua_pushcfunction(L, api_body_write);
  lua_setfield(L, -2, FUNC_WRITE);

  lua_pushcfunction(L, api_body_line);
  lua_setfield(L, -2, FUNC_LINE);

  lua_pushcfunction(L, api_body_link);
  lua_setfield(L, -2, FUNC_LINK);

  lua_pushcfunction(L, api_body_heading);
  lua_setfield(L, -2, FUNC_HEADING);

  lua_pushcfunction(L, api_body_quote);
  lua_setfield(L, -2, FUNC_QUOTE);

  lua_pushcfunction(L, api_body_block);
  lua_setfield(L, -2, FUNC_BLOCK);

  lua_pushcfunction(L, api_body_beginblock);
  lua_setfield(L, -2, FUNC_BEGIN_BLOCK);

  lua_pushcfunction(L, api_body_endblock);
  lua_setfield(L, -2, FUNC_END_BLOCK);

  lua_setglobal(L, TBL_BODY);
}

static void add_header_api_methods(lua_State* L) {
  lua_newtable(L);

  lua_pushcfunction(L, api_head_set_lang);
  lua_setfield(L, -2, FUNC_LANG);

  lua_pushcfunction(L, api_head_get_input);
  lua_setfield(L, -2, FUNC_INPUT);

  lua_pushcfunction(L, api_head_get_input_sensitive);
  lua_setfield(L, -2, FUNC_INPUT_SENSITIVE);

  lua_pushcfunction(L, api_head_get_cert);
  lua_setfield(L, -2, FUNC_CERT);

  lua_pushcfunction(L, api_head_has_cert);
  lua_setfield(L, -2, FUNC_CHECKCERT);

  lua_setglobal(L, TBL_HEADER);
}

static void add_response_ptr(lua_State* L, int index, response_t* response) {
  lua_pushlightuserdata(L, response);
  lua_setfield(L, index - 1, FLD_RESPONSE_PTR);
}

static void add_request_ptr(lua_State* L, int index, const request_t* request) {
  lua_pushlightuserdata(L, (request_t*)request);
  lua_setfield(L, index - 1, FLD_REQUEST_PTR);
}

static void init_scripting_api(lua_State* L, const request_t* request,
                               response_t* response) {
  luaL_openlibs(L);

  // add global response table
  lua_newtable(L);
  add_response_ptr(L, -1, response);
  lua_setglobal(L, TBL_RESPONSE);

  // add global request table
  lua_newtable(L);
  add_request_ptr(L, -1, request);
  lua_setglobal(L, TBL_REQUEST);

  // set the PATH global variable
  lua_pushstring(L, request->path + 1);
  lua_setglobal(L, FLD_PATH);

  // add user input as a global variable, if present
  if (request->input != NULL) {
    lua_pushstring(L, request->input);
    lua_setglobal(L, FLD_INPUT);
  }

  add_body_api_methods(L);
  add_header_api_methods(L);
}

static void init_response_buffer(lua_State* L) {
  lua_getglobal(L, TBL_RESPONSE);
  lua_pushliteral(L, "\0");
  lua_setfield(L, -2, FLD_BUFFER);
  lua_pop(L, 1);
}

static void add_package_path(lua_State* L, const char* path) {
  if (path == NULL) {
    return;
  }

  // skip the first forward-slash
  ++path;

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

script_ctx_t* init_script(const request_t* request, response_t* response) {
  script_ctx_t* ctx = malloc(sizeof(script_ctx_t));
  if (ctx == NULL) {
    LOG_ERROR("Failed to allocate space for the script context");
    return NULL;
  }

  ctx->result = NULL;
  ctx->result_len = 0;
  ctx->language = NULL;

  ctx->L = luaL_newstate();
  init_scripting_api(ctx->L, request, response);
  add_package_path(ctx->L, request->path);

  return ctx;
}

void destroy_script(script_ctx_t* ctx) {
  if (ctx != NULL) {
    if (ctx->L != NULL) {
      lua_close(ctx->L);
    }

    if (ctx->language != NULL) {
      free(ctx->language);
    }

    if (ctx->result != NULL) {
      free(ctx->result);
    }

    free(ctx);
  }
}

int run_script(script_ctx_t* ctx, char* contents) {
  lua_State* L = ctx->L;

  init_response_buffer(L);

  // free output buffer allocation from prior run if need be
  if (ctx->result != NULL) {
    free(ctx->result);
    ctx->result = NULL;
  }

  if (luaL_dostring(L, contents) != LUA_OK) {
    LOG_ERROR("Error running Lua script: %s", lua_tostring(L, -1));
    return RUN_SCRIPT_FAILURE;
  }

  // clear stack
  lua_pop(L, lua_gettop(L));

  // get response table
  lua_getglobal(L, TBL_RESPONSE);
  if (lua_isnoneornil(L, -1)) {
    return RUN_SCRIPT_FAILURE;
  }

  // get buffer field
  lua_getfield(L, -1, FLD_BUFFER);
  if (!lua_isnoneornil(L, -1) && lua_isstring(L, -1)) {
    const char* buffer = lua_tolstring(L, -1, &ctx->result_len);
    ctx->result = strndup(buffer, ctx->result_len);
  }

  lua_pop(L, lua_gettop(L));

  return 0;
}

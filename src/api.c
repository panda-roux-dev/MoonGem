#include <lauxlib.h>
#include <lua.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cert.h"
#include "gemini.h"
#include "log.h"
#include "script.h"
#include "status.h"
#include "util.h"

#define LINK_TOKEN "=>"
#define HEADER_TOKEN "#"
#define QUOTE_TOKEN ">"
#define BLOCK_TOKEN "```"
#define SPACE " "
#define NEWLINE "\n"

#define DEFAULT_MSG_INPUT_REQUIRED "Input required"
#define DEFAULT_MSG_CERT_REQUIRED "Client certificate required"

#define FLD_CERT_FINGERPRINT "fingerprint"
#define FLD_CERT_EXPIRATION "not_after"

static void set_interrupt_response(response_t* response, int status,
                                   const char* meta) {
  response->interrupted = true;
  response->meta = strdup(meta);
  response->status = status;
}

int api_head_set_lang(lua_State* L) {
  lua_settop(L, 1);

  const char* lang = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  // free the previous value if one exists
  if (response->language != NULL) {
    free(response->language);
  }

  response->language = strdup(lang);

  return 0;
}

int api_head_get_input(lua_State* L) {
  lua_settop(L, 1);

  lua_getglobal(L, FLD_INPUT);
  if (lua_isnoneornil(L, -1)) {
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
    response_t* response = (response_t*)lua_touserdata(L, -1);

    if (lua_isnoneornil(L, 1)) {
      set_interrupt_response(response, STATUS_INPUT,
                             DEFAULT_MSG_INPUT_REQUIRED);
    } else {
      const char* prompt = luaL_checkstring(L, 1);
      set_interrupt_response(response, STATUS_INPUT, prompt);
    }

    return 0;
  }

  return 1;
}

int api_head_get_input_sensitive(lua_State* L) {
  lua_settop(L, 1);

  lua_getglobal(L, FLD_INPUT);
  if (lua_isnoneornil(L, -1)) {
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
    response_t* response = (response_t*)lua_touserdata(L, -1);

    if (lua_isnoneornil(L, 1)) {
      set_interrupt_response(response, STATUS_SENSITIVE_INPUT,
                             DEFAULT_MSG_INPUT_REQUIRED);
    } else {
      const char* prompt = luaL_checkstring(L, 1);
      set_interrupt_response(response, STATUS_SENSITIVE_INPUT, prompt);
    }

    return 0;
  }

  return 1;
}

int api_head_temp_redirect(lua_State* L) {
  lua_settop(L, 1);

  const char* uri = luaL_checkstring(L, 1);
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);
  set_interrupt_response(response, STATUS_TEMPORARY_REDIRECT, uri);
  return 0;
}

int api_head_perm_redirect(lua_State* L) {
  lua_settop(L, 1);

  const char* uri = luaL_checkstring(L, 1);
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);
  set_interrupt_response(response, STATUS_PERMANENT_REDIRECT, uri);
  return 0;
}

int api_head_get_cert(lua_State* L) {
  lua_settop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  client_cert_t* cert = request->cert;
  if (!cert->initialized) {
    // no cert provided; request one from the client
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
    response_t* response = (response_t*)lua_touserdata(L, -1);

    if (lua_isnoneornil(L, 2)) {
      set_interrupt_response(response, STATUS_CLIENT_CERTIFICATE_REQUIRED,
                             DEFAULT_MSG_CERT_REQUIRED);
    } else {
      const char* prompt = luaL_checkstring(L, 2);
      set_interrupt_response(response, STATUS_CLIENT_CERTIFICATE_REQUIRED,
                             prompt);
    }

    return 0;
  }

  // return a new table { fingerprint, not_after }
  lua_newtable(L);

  lua_pushstring(L, cert->fingerprint);
  lua_setfield(L, -2, FLD_CERT_FINGERPRINT);

  lua_pushinteger(L, cert->not_after);
  lua_setfield(L, -2, FLD_CERT_EXPIRATION);

  return 1;
}

int api_head_has_cert(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  lua_pushboolean(L, request->cert->initialized);

  return 1;
}

int api_body_include(lua_State* L) {
  lua_settop(L, 1);

  const char* path = luaL_checkstring(L, 1);

  char* contents = NULL;
  size_t file_len = read_file(path, &contents);
  if (contents == NULL) {
    lua_pushfstring(L, "Failed to include file %s", path);
    lua_error(L);
    return 0;
  }

  if (file_len > 0) {
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
    struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);
    evbuffer_add_printf(buffer, "%s" NEWLINE, contents);
  }

  free(contents);

  return 0;
}

int api_body_write(lua_State* L) {
  lua_settop(L, 1);

  const char* text = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  // TODO: find out why there's a memory error here
  evbuffer_add_printf(buffer, "%s", text);

  return 0;
}

int api_body_line(lua_State* L) {
  lua_settop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  const char* text = lua_tostring(L, 1);
  if (text != NULL) {
    evbuffer_add_printf(buffer, "%s" NEWLINE, text);
  } else {
    evbuffer_add_printf(buffer, "%s", NEWLINE);
  }

  return 0;
}

int api_body_link(lua_State* L) {
  lua_settop(L, 2);

  const char* url = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  if (!lua_isstring(L, 2)) {
    // URL only, no alt-text

    evbuffer_add_printf(buffer, LINK_TOKEN " %s" NEWLINE, url);
  } else {
    // URL + alt-text

    const char* alt = luaL_checkstring(L, 2);
    evbuffer_add_printf(buffer, LINK_TOKEN " %s %s" NEWLINE, url, alt);
  }

  return 0;
}

int api_body_heading(lua_State* L) {
  lua_settop(L, 2);

  const char* text = luaL_checkstring(L, 1);

  int level = luaL_optinteger(L, 2, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  for (int i = 0; i < level; ++i) {
    evbuffer_add(buffer, HEADER_TOKEN, sizeof(HEADER_TOKEN) - 1);
  }

  evbuffer_add_printf(buffer, " %s" NEWLINE, text);

  return 0;
}

int api_body_quote(lua_State* L) {
  lua_settop(L, 1);

  const char* text = luaL_checkstring(L, 2);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add_printf(buffer, QUOTE_TOKEN " %s" NEWLINE, text);

  return 0;
}

int api_body_block(lua_State* L) {
  lua_settop(L, 1);

  const char* text = luaL_checkstring(L, 2);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add_printf(
      buffer, BLOCK_TOKEN NEWLINE "%s" NEWLINE BLOCK_TOKEN NEWLINE, text);

  return 0;
}

int api_body_beginblock(lua_State* L) {
  lua_settop(L, 1);

  const char* alt = luaL_checkstring(L, 2);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  if (alt == NULL) {
    evbuffer_add(buffer, BLOCK_TOKEN NEWLINE, sizeof(BLOCK_TOKEN NEWLINE) - 1);
  } else {
    evbuffer_add_printf(buffer, BLOCK_TOKEN "%s" NEWLINE, alt);
  }

  return 0;
}

int api_body_endblock(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add(buffer, BLOCK_TOKEN NEWLINE, sizeof(BLOCK_TOKEN NEWLINE) - 1);

  return 0;
}

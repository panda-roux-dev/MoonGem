#include <lauxlib.h>
#include <lua.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "cert.h"
#include "gemini.h"
#include "log.h"
#include "script.h"
#include "status.h"
#include "store.h"
#include "uri.h"

#define LINK_TOKEN "=>"
#define HEADER_TOKEN "#"
#define QUOTE_TOKEN ">"
#define BLOCK_TOKEN "```"
#define SPACE " "
#define NEWLINE "\n"
#define PATH_DEFAULT "/"

#define FLD_CERT_FINGERPRINT "fingerprint"
#define FLD_CERT_EXPIRATION "not_after"

#define FLD_STORE_LENGTH "length"
#define FLD_STORE_CAPACITY "capacity"
#define FLD_STORE_DATA_SIZE "data_size"

static void set_interrupt_response(response_t* response, int status,
                                   const char* meta) {
  response->interrupted = true;
  response->status = status;
  set_response_meta(response, meta);
}

int api_set_path(lua_State* L) {
  lua_settop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  if (request->uri->path != NULL) {
    free(request->uri->path);
    request->uri->path = NULL;
  }

  if (!lua_isnoneornil(L, 1)) {
    request->uri->path = strndup(lua_tostring(L, 1), URI_PATH_MAX);
  } else {
    request->uri->path = strdup(PATH_DEFAULT);
  }

  return 0;
}

int api_interrupt(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);
  response->interrupted = true;
  return 0;
}

int api_set_input(lua_State* L) {
  lua_settop(L, 1);

  if (!lua_isnoneornil(L, 1)) {
    lua_pushstring(L, luaL_checkstring(L, 1));
  } else {
    lua_pushnil(L);
  }

  lua_setfield(L, LUA_REGISTRYINDEX, FLD_INPUT);

  return 0;
}

int api_set_lang(lua_State* L) {
  lua_settop(L, 1);

  const char* lang = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_response_lang(response, lang);

  return 0;
}

int api_set_mimetype(lua_State* L) {
  lua_settop(L, 1);

  const char* mimetype = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_response_mime(response, mimetype);

  return 0;
}

int api_get_input(lua_State* L) {
  lua_settop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_INPUT);
  if (lua_isnoneornil(L, -1)) {
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
    response_t* response = (response_t*)lua_touserdata(L, -1);
    const char* meta = luaL_optstring(L, 1, META_INPUT);

    set_interrupt_response(response, STATUS_INPUT, meta);

    return 0;
  }

  return 1;
}

int api_get_input_sensitive(lua_State* L) {
  lua_settop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_INPUT);
  if (lua_isnoneornil(L, -1)) {
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
    response_t* response = (response_t*)lua_touserdata(L, -1);
    const char* meta = luaL_optstring(L, 1, META_SENSITIVE_INPUT);

    set_interrupt_response(response, STATUS_INPUT, meta);

    return 0;
  }

  return 1;
}

int api_has_input(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_INPUT);
  if (lua_isnoneornil(L, -1)) {
    lua_pushboolean(L, true);
  } else {
    lua_pushboolean(L, true);
  }

  return 1;
}

int api_get_path(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  if (request->uri != NULL && request->uri->path != NULL) {
    lua_pushstring(L, request->uri->path);
  } else {
    lua_pushnil(L);
  }

  return 1;
}

int api_get_raw_path(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  if (request->uri != NULL && request->uri->raw_path != NULL) {
    lua_pushstring(L, request->uri->raw_path);
  } else {
    lua_pushnil(L);
  }

  return 1;
}

int api_success(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);
  set_response_status(response, STATUS_SUCCESS, NULL);
  return 0;
}

int api_temp_redirect(lua_State* L) {
  lua_settop(L, 1);

  const char* uri = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);
  set_interrupt_response(response, STATUS_TEMPORARY_REDIRECT, uri);
  return 0;
}

int api_perm_redirect(lua_State* L) {
  lua_settop(L, 1);

  const char* uri = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);
  set_interrupt_response(response, STATUS_PERMANENT_REDIRECT, uri);
  return 0;
}

int api_temp_failure(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_TEMPORARY_FAILURE);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_TEMPORARY_FAILURE, meta);

  return 0;
}

int api_unavailable(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_SERVER_UNAVAILABLE);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_SERVER_UNAVAILABLE, meta);

  return 0;
}

int api_cgi_error(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_CGI_ERROR);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_CGI_ERROR, meta);

  return 0;
}

int api_proxy_error(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_PROXY_ERROR);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_PROXY_ERROR, meta);

  return 0;
}

int api_slow_down(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_SLOW_DOWN);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_SLOW_DOWN, meta);

  return 0;
}

int api_perm_failure(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_PERMANENT_FAILURE);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_PERMANENT_FAILURE, meta);

  return 0;
}

int api_not_found(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_NOT_FOUND);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_NOT_FOUND, meta);

  return 0;
}

int api_gone(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_GONE);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_GONE, meta);

  return 0;
}

int api_proxy_refused(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_PROXY_REQUEST_REFUSED);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_PROXY_REQUEST_REFUSED, meta);

  return 0;
}

int api_bad_request(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_BAD_REQUEST);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_BAD_REQUEST, meta);

  return 0;
}

int api_cert_required(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_CLIENT_CERTIFICATE_REQUIRED);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_CLIENT_CERTIFICATE_REQUIRED, meta);

  return 0;
}

int api_cert_unauthorized(lua_State* L) {
  lua_settop(L, 1);

  const char* meta = luaL_optstring(L, 1, META_CERTIFICATE_NOT_AUTHORIZED);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
  response_t* response = (response_t*)lua_touserdata(L, -1);

  set_interrupt_response(response, STATUS_CERTIFICATE_NOT_AUTHORIZED, meta);

  return 0;
}

int api_get_cert(lua_State* L) {
  lua_settop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  client_cert_t* cert = request->cert;
  if (cert == NULL || !cert->initialized) {
    // no cert provided; request one from the client
    lua_getfield(L, LUA_REGISTRYINDEX, FLD_RESPONSE);
    response_t* response = (response_t*)lua_touserdata(L, -1);

    const char* prompt = luaL_optstring(L, 1, META_CLIENT_CERTIFICATE_REQUIRED);
    set_interrupt_response(response, STATUS_CLIENT_CERTIFICATE_REQUIRED,
                           prompt);

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

int api_has_cert(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_REQUEST);
  request_t* request = (request_t*)lua_touserdata(L, -1);

  lua_pushboolean(L, request->cert->initialized);

  return 1;
}

int api_include(lua_State* L) {
  lua_settop(L, 1);

  const char* path = luaL_checkstring(L, 1);

  FILE* fp;
  struct stat st;
  if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
      (fp = fopen(path, "rb")) == NULL) {
    luaL_error(L,
               "Failed to include \"%s\" because it doesn't exist or is not a "
               "regular file",
               path);
    return 0;
  }

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add_file(buffer, fileno(fp), 0, -1);

  return 0;
}

int api_write(lua_State* L) {
  lua_settop(L, 1);

  const char* text = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add_printf(buffer, "%s", text);

  return 0;
}

int api_line(lua_State* L) {
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

int api_link(lua_State* L) {
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

int api_heading(lua_State* L) {
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

int api_quote(lua_State* L) {
  lua_settop(L, 1);

  const char* text = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add_printf(buffer, QUOTE_TOKEN " %s" NEWLINE, text);

  return 0;
}

int api_block(lua_State* L) {
  lua_settop(L, 1);

  const char* text = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add_printf(
      buffer, BLOCK_TOKEN NEWLINE "%s" NEWLINE BLOCK_TOKEN NEWLINE, text);

  return 0;
}

int api_beginblock(lua_State* L) {
  lua_settop(L, 1);

  const char* alt = luaL_checkstring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  if (alt == NULL) {
    evbuffer_add(buffer, BLOCK_TOKEN NEWLINE, sizeof(BLOCK_TOKEN NEWLINE) - 1);
  } else {
    evbuffer_add_printf(buffer, BLOCK_TOKEN "%s" NEWLINE, alt);
  }

  return 0;
}

int api_endblock(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_BUFFER);
  struct evbuffer* buffer = (struct evbuffer*)lua_touserdata(L, -1);

  evbuffer_add(buffer, BLOCK_TOKEN NEWLINE, sizeof(BLOCK_TOKEN NEWLINE) - 1);

  return 0;
}

int api_set_store_value(lua_State* L) {
  char* key = (char*)lua_tostring(L, 2);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_STORE);
  store_t* store = lua_touserdata(L, -1);

  if (!lua_isnoneornil(L, 3)) {
    char* value = (char*)lua_tostring(L, 3);
    insert_into_store(store, key, value);
  } else {
    delete_from_store(store, key);
  }

  return 0;
}

int api_get_store_value(lua_State* L) {
  char* key = (char*)lua_tostring(L, 2);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_STORE);
  store_t* store = lua_touserdata(L, -1);

  const char* result = get_from_store(store, key);
  if (result == NULL) {
    lua_pushnil(L);
  } else {
    lua_pushstring(L, result);
  }

  return 1;
}

int api_dump_store(lua_State* L) {
  lua_settop(L, 1);

  const char* path = lua_tostring(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_STORE);
  store_t* store = lua_touserdata(L, -1);

  FILE* out = path == NULL ? stdout : fopen(path, "w");
  if (out == NULL) {
    luaL_error(L, "Failed to open output stream");
  } else {
    fprintf(out, "position\tkey\tlength\tdata\n");
    for (size_t i = 0; i < store->cell_count; i++) {
      cell_t* cell = &store->cells[i];
      if (cell->key == 0 || cell->deleted) {
        continue;
      }

      fprintf(out, "%zu\t%zu\t%zu\t%s\n", i, cell->key, cell->length,
              cell->data);
    }
  }

  return 0;
}

int api_get_store_length(lua_State* L) {
  lua_getfield(L, LUA_REGISTRYINDEX, FLD_STORE);
  store_t* store = lua_touserdata(L, -1);

  lua_pushinteger(L, store->stored_count);

  return 1;
}

int api_get_store_info(lua_State* L) {
  lua_newtable(L);

  lua_getfield(L, LUA_REGISTRYINDEX, FLD_STORE);
  store_t* store = lua_touserdata(L, -1);

  lua_pushinteger(L, store->stored_count);
  lua_setfield(L, -2, FLD_STORE_LENGTH);

  lua_pushinteger(L, store->cell_count);
  lua_setfield(L, -2, FLD_STORE_CAPACITY);

  size_t total_length = 0;
  for (size_t i = 0; i < store->cell_count; i++) {
    cell_t* cell = &store->cells[i];
    if (cell->key == 0 || cell->deleted) {
      continue;
    }

    total_length += cell->length;
  }

  lua_pushinteger(L, total_length);
  lua_setfield(L, -2, FLD_STORE_DATA_SIZE);

  return 1;
}

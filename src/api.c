#include <lauxlib.h>
#include <lua.h>
#include <stdio.h>

#include "log.h"
#include "script.h"
#include "util.h"

#define SCRIPT_ERR(L, fmt, ...)             \
  {                                         \
    lua_pushfstring(L, fmt, ##__VA_ARGS__); \
    lua_error(L);                           \
  }

#define LINK_TOKEN "=>"
#define HEADER_TOKEN "#"
#define QUOTE_TOKEN ">"
#define BLOCK_TOKEN "```"
#define SPACE " "
#define NEWLINE "\n"

int api_head_set_lang(lua_State* L) { return 0; }

int api_body_include(lua_State* L) {
  const char* path = luaL_checkstring(L, 2);

  char* contents = NULL;
  size_t file_len = read_file(path, &contents);
  if (contents == NULL) {
    SCRIPT_ERR(L, "Failed to read file at %s", path);
    return 0;
  }

  if (file_len > 0) {
    lua_getfield(L, 1, TBL_RESPONSE);
    lua_getfield(L, -1, FLD_BUFFER);

    lua_pushfstring(L, "%s" NEWLINE, contents);

    lua_concat(L, 2);
    lua_setfield(L, -2, FLD_BUFFER);
  }

  return 0;
}

int api_body_write(lua_State* L) {
  const char* text = luaL_checkstring(L, 2);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  lua_pushstring(L, text);

  lua_concat(L, 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_line(lua_State* L) {
  const char* text = luaL_checkstring(L, 2);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  lua_pushfstring(L, "%s" NEWLINE, text);

  lua_concat(L, 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_link(lua_State* L) {
  const char* url = luaL_checkstring(L, 2);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  if (!lua_isstring(L, 3)) {
    // URL only, no alt-text

    lua_pushfstring(L, LINK_TOKEN " %s" NEWLINE, url);
  } else {
    // URL + alt-text

    const char* alt = luaL_checkstring(L, 3);
    lua_pushfstring(L, LINK_TOKEN " %s %s" NEWLINE, url, alt);
  }

  lua_concat(L, 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_heading(lua_State* L) {
  const char* text = luaL_checkstring(L, 2);

  int level = luaL_optinteger(L, 3, 1);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  for (int i = 0; i < level; ++i) {
    lua_pushliteral(L, "#");
  }

  lua_pushfstring(L, " %s" NEWLINE, text);

  lua_concat(L, level + 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_quote(lua_State* L) {
  const char* text = luaL_checkstring(L, 2);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  lua_pushfstring(L, QUOTE_TOKEN " %s" NEWLINE, text);

  lua_concat(L, 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_block(lua_State* L) {
  const char* text = luaL_checkstring(L, 2);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  lua_pushfstring(L, BLOCK_TOKEN NEWLINE "%s" NEWLINE BLOCK_TOKEN NEWLINE,
                  text);

  lua_concat(L, 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_beginblock(lua_State* L) {
  const char* alt = luaL_checkstring(L, 2);

  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  if (alt == NULL) {
    lua_pushliteral(L, BLOCK_TOKEN NEWLINE);
  } else {
    lua_pushfstring(L, BLOCK_TOKEN "%s" NEWLINE, alt);
  }

  lua_concat(L, 2);
  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

int api_body_endblock(lua_State* L) {
  lua_getfield(L, 1, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);
  lua_pushliteral(L, BLOCK_TOKEN NEWLINE);
  lua_concat(L, 2);

  lua_setfield(L, -2, FLD_BUFFER);

  return 0;
}

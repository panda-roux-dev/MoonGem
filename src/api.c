#include <lua.h>
#include <stdio.h>

#include "log.h"
#include "script.h"
#include "util.h"

#define ARG_COUNT(L, n)                                                        \
  {                                                                            \
    int argc = lua_gettop(L);                                                  \
    if (argc < (n) + 1) {                                                      \
      lua_pushfstring(L,                                                       \
                      "Too few arguments passed to %s: expected %d, found %d", \
                      __func__, n, argc - 1);                                  \
      lua_error(L);                                                            \
      return 0;                                                                \
    }                                                                          \
  }

#define ARG_TYPE(L, n, type)                                                \
  {                                                                         \
    if (!lua_is##type(L, (n) + 1)) {                                        \
      lua_pushfstring(                                                      \
          L, "Argument %d passed to %s in an invalid type; expected %s", n, \
          __func__, #type);                                                 \
      lua_error(L);                                                         \
      return 0;                                                             \
    }                                                                       \
  }

#define SCRIPT_ERR(L, fmt, ...)             \
  {                                         \
    lua_pushfstring(L, fmt, ##__VA_ARGS__); \
    lua_error(L);                           \
  }

#define ARG(n) (n + 1)
#define SELF 1
#define LINK_TOKEN "=>"
#define HEADER_TOKEN "#"
#define QUOTE_TOKEN ">"
#define BLOCK_TOKEN "```"
#define SPACE " "
#define NEWLINE "\n"

int api_head_set_lang(lua_State* L);

int api_body_include(lua_State* L) {
  ARG_COUNT(L, 1);
  ARG_TYPE(L, 1, string);

  const char* path = lua_tostring(L, ARG(1));
  lua_pop(L, 1);

  char* contents = NULL;
  size_t file_len = read_file(path, &contents);
  if (contents == NULL) {
    SCRIPT_ERR(L, "Failed to read file at %s", path);
    return 0;
  }

  if (file_len > 0) {
    lua_getfield(L, SELF, TBL_RESPONSE);
    lua_getfield(L, -1, FLD_BUFFER);
    lua_pushstring(L, contents);
    lua_pushliteral(L, "\n");
    lua_concat(L, 3);

    lua_setfield(L, SELF + 1, FLD_BUFFER);
  }

  return 0;
}

int api_body_write(lua_State* L) {
  ARG_COUNT(L, 1);
  ARG_TYPE(L, 1, string);

  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);
  lua_rotate(L, 2, -1);
  lua_concat(L, 2);
  lua_setfield(L, 2, FLD_BUFFER);

  return 0;
}

int api_body_line(lua_State* L) {
  ARG_COUNT(L, 1);
  ARG_TYPE(L, 1, string);

  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);
  lua_rotate(L, 2, -1);
  lua_pushliteral(L, NEWLINE);
  lua_concat(L, 3);
  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

int api_body_link(lua_State* L) {
  ARG_COUNT(L, 1);

  if (lua_gettop(L) == 2) {
    ARG_TYPE(L, 1, string);

    // URL only, no alt-text

    lua_pushliteral(L, SPACE);
    lua_pushliteral(L, LINK_TOKEN);
    lua_getfield(L, SELF, TBL_RESPONSE);
    lua_getfield(L, -1, FLD_BUFFER);
    lua_rotate(L, 2, 2);
    lua_rotate(L, 4, 1);
    lua_rotate(L, 5, 1);
    lua_pushliteral(L, NEWLINE);
    lua_concat(L, 5);
  } else {
    ARG_TYPE(L, 1, string);
    ARG_TYPE(L, 2, string);

    // URL + alt-text

    lua_pushliteral(L, SPACE);
    lua_pushliteral(L, LINK_TOKEN);
    lua_pushliteral(L, SPACE);
    lua_getfield(L, SELF, TBL_RESPONSE);
    lua_getfield(L, -1, FLD_BUFFER);
    lua_rotate(L, 2, 2);
    lua_rotate(L, 4, 2);
    lua_rotate(L, 7, 1);
    lua_pushliteral(L, NEWLINE);
    lua_concat(L, 7);
  }

  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

int api_body_heading(lua_State* L) {
  ARG_COUNT(L, 2);
  ARG_TYPE(L, 1, string);
  ARG_TYPE(L, 2, integer);

  int level = lua_tointeger(L, ARG(2));
  lua_pop(L, 1);

  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  for (int i = 0; i < level; ++i) {
    lua_pushliteral(L, "#");
  }

  lua_pushliteral(L, SPACE);
  lua_rotate(L, 2, -1);
  lua_pushliteral(L, NEWLINE);
  lua_concat(L, level + 4);

  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

int api_body_quote(lua_State* L) {
  ARG_COUNT(L, 1);
  ARG_TYPE(L, 1, string);

  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);

  lua_pushliteral(L, QUOTE_TOKEN);
  lua_rotate(L, 2, -1);
  lua_pushliteral(L, NEWLINE);
  lua_concat(L, 4);
  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

int api_body_block(lua_State* L) {
  ARG_COUNT(L, 1);
  ARG_TYPE(L, 1, string);

  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);
  lua_pushliteral(L, BLOCK_TOKEN);
  lua_pushliteral(L, NEWLINE);
  lua_pushliteral(L, BLOCK_TOKEN);
  lua_pushliteral(L, NEWLINE);
  lua_rotate(L, 2, -1);
  lua_rotate(L, 5, -2);
  lua_pushliteral(L, NEWLINE);
  lua_concat(L, 7);
  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

int api_body_beginblock(lua_State* L) {
  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);
  lua_pushliteral(L, BLOCK_TOKEN);

  if (lua_gettop(L) >= 2) {
    // optional first argument for alt-text
    lua_rotate(L, 2, -1);
    lua_pushliteral(L, NEWLINE);
    lua_concat(L, 4);
  } else {
    lua_pushliteral(L, NEWLINE);
    lua_concat(L, 3);
  }

  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

int api_body_endblock(lua_State* L) {
  lua_getfield(L, SELF, TBL_RESPONSE);
  lua_getfield(L, -1, FLD_BUFFER);
  lua_pushliteral(L, BLOCK_TOKEN);
  lua_pushliteral(L, NEWLINE);
  lua_concat(L, 3);

  lua_setfield(L, SELF + 1, FLD_BUFFER);

  return 0;
}

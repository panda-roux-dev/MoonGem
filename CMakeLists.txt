cmake_minimum_required(VERSION 3.18)

project(moongem VERSION 2.3.3 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# default to Release-mode
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# set some variables
set(MOONGEM_EXE ${CMAKE_PROJECT_NAME})
set(MOONGEM_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MOONGEM_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(MOONGEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(SRC_FILES
  "main.c"
  "options.c"
  "script.c"
  "api.c"
  "gemini.c"
  "parse.c"
  "net.c"
  "cert.c"
  "uri.c"
  "util.c"
  "signals.c"
  "store.c")

# add external library directory
add_subdirectory(${MOONGEM_LIB_DIR})

# find libraries
find_package(PkgConfig)

if (PKG_CONFIG_FOUND)
  pkg_check_modules(EVT REQUIRED IMPORTED_TARGET libevent_core)
  pkg_check_modules(EVT_SSL REQUIRED IMPORTED_TARGET libevent_openssl)
  pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)
  pkg_check_modules(PCRE REQUIRED IMPORTED_TARGET libpcre2-posix)
  pkg_check_modules(MAGIC REQUIRED IMPORTED_TARGET libmagic)
  pkg_search_module(LUA REQUIRED IMPORTED_TARGET lua5.4 lua5.3)
endif()

# prepend the 'src' directory name to each of the source files
list(TRANSFORM SRC_FILES PREPEND "${MOONGEM_SRC_DIR}/")

# set up the binary
add_executable(${MOONGEM_EXE} ${SRC_FILES})
target_link_libraries(${MOONGEM_EXE} PRIVATE
  ${ARGPARSE_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  PkgConfig::MAGIC
  PkgConfig::LUA
  PkgConfig::EVT
  PkgConfig::EVT_SSL
  PkgConfig::OPENSSL
  PkgConfig::PCRE)
target_include_directories(${MOONGEM_EXE} PRIVATE
  ${MOONGEM_INCLUDE_DIR}
  ${ARGPARSE_INCLUDE_DIR}
  ${MAGIC_INCLUDES}
  ${LUA_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIRS}
  ${WYHASH_INCLUDE_DIR}
  ${EVT_INCLUDE_DIRS}
  ${EVT_SSL_INCLUDE_DIRS}
  ${PCRE_INCLUDE_DIRS})

# optionally disable logging to reduce the binary size
if(DISABLE_LOGGING)
  target_compile_definitions(${MOONGEM_EXE} PRIVATE MOONGEM_DISABLE_LOGGING)
endif()

target_compile_definitions(${MOONGEM_EXE} PRIVATE
  MOONGEM_VERSION="${CMAKE_PROJECT_VERSION}")

add_executable(store_test src/test/store.c src/store.c)
target_compile_options(store_test PRIVATE -O0 -ggdb -DDEBUG)
target_include_directories(store_test PRIVATE 
  ${MOONGEM_INCLUDE_DIR}
  ${WYHASH_INCLUDE_DIR})

add_custom_target(test
  COMMAND store_test
  USES_TERMINAL)

install(TARGETS ${MOONGEM_EXE} DESTINATION bin)

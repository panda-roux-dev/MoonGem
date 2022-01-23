cmake_minimum_required(VERSION 3.18)

project(moongem VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# default to Release-mode
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type specified, defaulting to Release")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

# set some variables
set(MOONGEM_EXE moongem)
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
  "signals.c")

# set default compile flags
set(CMAKE_C_FLAGS_DEBUG
  "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -ggdb")
set(CMAKE_C_FLAGS_RELEASE
  "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections -flto -O2 -fmerge-all-constants -fdata-sections")

# add external library directory
add_subdirectory(${MOONGEM_LIB_DIR})

# find libraries
find_package(PkgConfig)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Lua 5.4 REQUIRED)

if (PKG_CONFIG_FOUND)
  pkg_check_modules(EVT libevent_core)
  pkg_check_modules(EVT_SSL libevent_openssl)
  pkg_check_modules(PCRE libpcre2-posix)
  pkg_check_modules(MAGIC libmagic)
endif()

# prepend the 'src' directory name to each of the source files
list(TRANSFORM SRC_FILES PREPEND "${MOONGEM_SRC_DIR}/")

# set up the binary
add_executable(${MOONGEM_EXE} ${SRC_FILES})
target_link_libraries(${MOONGEM_EXE} PRIVATE
  ${ARGPARSE_LIBRARIES}
  ${MAGIC_LIBRARIES}
  ${LUA_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  ${EVT_LIBRARIES}
  ${EVT_SSL_LIBRARIES}
  ${PCRE_LIBRARIES})
target_include_directories(${MOONGEM_EXE} PRIVATE
  ${MOONGEM_INCLUDE_DIR}
  ${ARGPARSE_INCLUDE_DIR}
  ${MAGIC_INCLUDES}
  ${LUA_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR}
  ${EVT_INCLUDE_DIRS}
  ${EVT_SSL_INCLUDE_DIRS}
  ${PCRE_INCLUDE_DIRS})

install(TARGETS ${MOONGEM_EXE} DESTINATION bin)

# optionally disable logging to reduce the binary size
if(DISABLE_LOGGING)
  target_compile_definitions(${MOONGEM_EXE} PRIVATE MOONGEM_DISABLE_LOGGING)
endif()

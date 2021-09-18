cmake_minimum_required(VERSION 3.18)

project(moongem VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# pull in extra CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

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
  "runtime.c"
  "buffer.c"
  "script.c"
  "api.c"
  "gemini.c"
  "parse.c"
  "net.c"
  "cert.c"
  "header.c"
  "util.c")

# set default compile flags
set(CMAKE_C_FLAGS_DEBUG
  "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -ggdb")
set(CMAKE_C_FLAGS_RELEASE
  "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections -flto -O2 -fmerge-all-constants -fdata-sections")

# libmicrohttpd requires this
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

# add external library directory
add_subdirectory(${MOONGEM_LIB_DIR})

# find libraries
find_package(PkgConfig)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Lua 5.4 REQUIRED)
find_package(LibMagic REQUIRED)
find_package(Threads REQUIRED)

if (PKG_CONFIG_FOUND)
  pkg_check_modules(MHD libmicrohttpd)
endif()

# enable the HTTP feature if it was not disabled
if (NOT DISABLE_HTTP AND MHD_FOUND)
  list(APPEND SRC_FILES "http.c")
endif()

# prepend the 'src' directory name to each of the source files
list(TRANSFORM SRC_FILES PREPEND "${MOONGEM_SRC_DIR}/")

# set up the binary
add_executable(${MOONGEM_EXE} ${SRC_FILES})
target_link_libraries(${MOONGEM_EXE} PRIVATE
  ${ARGPARSE_LIBRARIES}
  ${LIBMAGIC_LIBRARIES}
  ${LUA_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(${MOONGEM_EXE} PRIVATE
  ${MOONGEM_INCLUDE_DIR}
  ${ARGPARSE_INCLUDE_DIR}
  ${LIBMAGIC_INCLUDES}
  ${LUA_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR})

install(TARGETS ${MOONGEM_EXE} DESTINATION bin)

if (NOT DISABLE_HTTP)
  if (MHD_FOUND)
    # extra stuff for libmicrohttpd

    message(STATUS "The HTTP proxying feature is enabled; define DISABLE_HTTP if you would like to disable it.")
    target_link_libraries(${MOONGEM_EXE} PRIVATE ${MHD_LIBRARIES})
    target_include_directories(${MOONGEM_EXE} PRIVATE ${MHD_INCLUDE_DIRS})
    target_compile_options(${MOONGEM_EXE} PRIVATE ${MHD_CFLAGS_OTHER})
    target_compile_definitions(${MOONGEM_EXE} PRIVATE HTTP_PROXY_ENABLED=1)
  else()
    message(STATUS "libmicrohttpd was not found, so HTTP proxying will be unavailable.")
  endif()
endif()

# optionally disable logging to reduce the binary size
if(DISABLE_LOGGING)
  target_compile_definitions(${MOONGEM_EXE} PRIVATE MOONGEM_DISABLE_LOGGING)
endif()

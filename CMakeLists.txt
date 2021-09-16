cmake_minimum_required(VERSION 3.18)

project(moongem VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type specified, defaulting to Release")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

set(MOONGEM_EXE moongem)
set(MOONGEM_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MOONGEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(SRC_FILES
  "${MOONGEM_SRC_DIR}/main.c"
  "${MOONGEM_SRC_DIR}/script.c"
  "${MOONGEM_SRC_DIR}/api.c"
  "${MOONGEM_SRC_DIR}/gemini.c"
  "${MOONGEM_SRC_DIR}/parse.c"
  "${MOONGEM_SRC_DIR}/net.c"
  "${MOONGEM_SRC_DIR}/cert.c"
  "${MOONGEM_SRC_DIR}/header.c"
  "${MOONGEM_SRC_DIR}/util.c")

set(CMAKE_C_FLAGS_DEBUG
  "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -ggdb")
set(CMAKE_C_FLAGS_RELEASE
  "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections -flto -O2 -fmerge-all-constants -fdata-sections")

set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(PkgConfig)
pkg_check_modules(MHD libmicrohttpd)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Lua 5.4 REQUIRED)
find_package(LibMagic REQUIRED)
find_package(Threads REQUIRED)

add_executable(${MOONGEM_EXE} ${SRC_FILES})
target_link_libraries(${MOONGEM_EXE} PRIVATE
  ${LIBMAGIC_LIBRARIES}
  ${LUA_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(${MOONGEM_EXE} PRIVATE
  ${MOONGEM_INCLUDE_DIR}
  ${LIBMAGIC_INCLUDES}
  ${LUA_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR})

install(TARGETS ${MOONGEM_EXE} DESTINATION bin)

if (NOT DISABLE_HTTP)
  if (MHD_FOUND)
    message(STATUS "The HTTP proxying feature is enabled; define DISABLE_HTTP to disable it.")
    target_link_libraries(${MOONGEM_EXE} PRIVATE ${MHD_LIBRARIES})
    target_include_directories(${MOONGEM_EXE} PRIVATE ${MHD_INCLUDE_DIRS})
    target_compile_options(${MOONGEM_EXE} PRIVATE ${MHD_CFLAGS_OTHER})
    target_compile_definitions(${MOONGEM_EXE} PRIVATE HTTP_PROXY_ENABLED=1)
  else()
    message(STATUS "libmicrohttpd was not found, so HTTP proxying will be unavailable.")
  endif()
endif()

if(DISABLE_LOGGING)
  target_compile_definitions(${MOONGEM_EXE} PRIVATE MOONGEM_DISABLE_LOGGING)
endif()

cmake_minimum_required(VERSION 3.19.7)

project(moongem VERSION 0.1.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(MOONGEM_EXE moongem)
set(MOONGEM_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MOONGEM_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(SRC_FILES
  "${MOONGEM_SRC_DIR}/main.c"
  "${MOONGEM_SRC_DIR}/script.c"
  "${MOONGEM_SRC_DIR}/api.c"
  "${MOONGEM_SRC_DIR}/parse.c"
  "${MOONGEM_SRC_DIR}/net.c"
  "${MOONGEM_SRC_DIR}/util.c")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -ggdb")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -ffunction-sections -flto -O2 -fmerge-all-constants -fdata-sections")

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Lua 5.4 REQUIRED)
find_package(LibMagic REQUIRED)

add_executable(${MOONGEM_EXE} ${SRC_FILES})
target_link_libraries(${MOONGEM_EXE} PRIVATE
  ${LIBMAGIC_LIBRARIES}
  ${LUA_LIBRARIES}
  ${OPENSSL_LIBRARIES})
target_include_directories(${MOONGEM_EXE} PRIVATE
  ${MOONGEM_INCLUDE_DIR}
  ${LIBMAGIC_INCLUDES}
  ${LUA_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR})



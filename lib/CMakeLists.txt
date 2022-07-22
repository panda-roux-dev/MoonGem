# suppress 'option()' warning
cmake_policy(SET CMP0077 NEW)

set(ARGPARSE_SHARED OFF)
set(ARGPARSE_STATIC ON)
set(ARGPARSE_LIBRARIES argparse PARENT_SCOPE)
set(ARGPARSE_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/argparse" PARENT_SCOPE)
add_subdirectory(argparse)

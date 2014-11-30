cmake_minimum_required (VERSION 2.6)

SET(CMAKE_BUILD_TYPE Release CACHE STRING "If build type is not specified on command line, build Release")

project (mrtdreader)

INCLUDE(CheckIncludeFiles)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_subdirectory(src)
add_subdirectory(test)

cmake_minimum_required (VERSION 2.6)

SET(CMAKE_BUILD_TYPE Release CACHE STRING "If build type is not specified on command line, build Release")

project (mrtdreader)

find_package(PkgConfig)
INCLUDE(CheckIncludeFiles)

pkg_check_modules(NFC libnfc)
CHECK_INCLUDE_FILES(gcrypt.h HAVE_GCRYPT)

if(NOT NFC_FOUND)
    MESSAGE(FATAL_ERROR "The development files for libnfc are needed")
endif()

if(NOT HAVE_GCRYPT)
    MESSAGE(FATAL_ERROR "The development files for libgcrypt are needed")
endif()

set(MRTD_VERSION 0.1.4)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/mrtd.pc.in ${CMAKE_CURRENT_BINARY_DIR}/mrtd.pc)

if(${CMAKE_INSTALL_PREFIX} STREQUAL "/usr")
 install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mrtd.pc DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}/pkgconfig)
else()
 install(FILES ${CMAKE_CURRENT_BINARY_DIR}/mrtd.pc DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig)
endif()

add_subdirectory(src)
add_subdirectory(test)

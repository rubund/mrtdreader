add_library(mrtd SHARED bac.c bachelper.c fileread.c hardware.c crypto-gcrypt.c)
target_link_libraries(mrtd nfc usb)
target_link_libraries(mrtd gcrypt)

add_executable(mrtdreader mrtdreader.c)
target_link_libraries(mrtdreader mrtd)

set_target_properties(mrtd PROPERTIES VERSION 0.0.0 SOVERSION 0)

install(TARGETS mrtdreader DESTINATION bin)
if(${CMAKE_INSTALL_PREFIX} STREQUAL "/usr")
 install(TARGETS mrtd DESTINATION lib/${CMAKE_LIBRARY_ARCHITECTURE})
else()
 install(TARGETS mrtd DESTINATION lib)
endif()


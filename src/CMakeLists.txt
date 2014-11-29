add_executable(mrtdreader mrtdreader.c bac.c bachelper.c fileread.c hardware.c crypto-gcrypt.c)
target_link_libraries(mrtdreader nfc usb)
target_link_libraries(mrtdreader gcrypt)
install(TARGETS mrtdreader DESTINATION bin)


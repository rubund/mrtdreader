add_executable(test1 test1.c ../src/bachelper.c ../src/crypto-gcrypt.c)
target_link_libraries(test1 gcrypt)


cmake_minimum_required(VERSION 3.9)
project(cPace LANGUAGES C DESCRIPTION
    "An C implementation of cPace that uses OpenSSL as the crypto library"
)

find_package(OpenSSL 1.1.0 REQUIRED COMPONENTS Crypto)

add_library(cpace STATIC cpace.c cpace.h)
target_link_libraries(cpace PRIVATE OpenSSL::Crypto)

add_executable(test test.c cpace.h)
target_link_libraries(test cpace)

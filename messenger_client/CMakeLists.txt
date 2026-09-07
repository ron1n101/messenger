cmake_minimum_required(VERSION 3.20)
project(messenger_client_crypto LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
add_library(crypto_core
    src/crypto/secure_memory.cpp
    src/crypto/keys.cpp
    src/crypto/diffie_helman.cpp
    src/crypto/signature.cpp
    )
target_include_directories(crypto_core PUBLIC src)
target_link_libraries(crypto_core PUBLIC OpenSSL::Crypto)

enable_testing()
add_subdirectory(tests)

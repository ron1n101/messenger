cmake_minimum_required(VERSION 3.20)
project(messenger_client_crypto LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
add_subdirectory(third_party/libsignal-protocol-c EXCLUDE_FROM_ALL)

add_library(crypto_core
    src/crypto/secure_memory.cpp
    src/crypto/keys.cpp
    src/crypto/diffie_helman.cpp
    src/crypto/signature.cpp
    src/crypto/helper.cpp
    src/crypto/kdf.cpp
    src/crypto/aead.cpp
    src/crypto/types.h
    src/crypto/aead_internal.h
    src/crypto/hmac.cpp
    src/crypto/hmac.h
    src/crypto/aes_cbc.cpp
    src/crypto/aes_cbc.h
    src/crypto/signal_bridge.cpp
    src/crypto/signal_bridge.h
    )
target_include_directories(crypto_core PUBLIC src third_party/libsignal-protocol-c/src)
target_link_libraries(crypto_core PUBLIC OpenSSL::Crypto signal-protocol-c)

enable_testing()
add_subdirectory(tests)

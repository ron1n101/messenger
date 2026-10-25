add_executable(crypto_tests
${CMAKE_SOURCE_DIR}/third_party/catch_amalgamated.cpp
test_keys.cpp
test_dh.cpp
test_signature.cpp
test_kdf.cpp
test_aead.cpp
test_hmac.cpp
test_secure_memory.cpp
test_aes_cbc.cpp
test_signal_link.cpp
test_signal_bridge.cpp
test_hmac_stream.cpp
test_sha512.cpp)

target_include_directories(crypto_tests PRIVATE ${CMAKE_SOURCE_DIR}/third_party)
target_link_libraries(crypto_tests PRIVATE crypto_core)

include(${CMAKE_SOURCE_DIR}/third_party/Catch.cmake)
catch_discover_tests(crypto_tests)

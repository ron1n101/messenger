add_executable(crypto_tests
${CMAKE_SOURCE_DIR}/third_party/catch_amalgamated.cpp
test_keys.cpp
)
target_include_directories(crypto_tests PRIVATE ${CMAKE_SOURCE_DIR}/third_party)
target_link_libraries(crypto_tests PRIVATE crypto_core)

include(${CMAKE_SOURCE_DIR}/third_party/Catch.cmake)
catch_discover_tests(crypto_tests)

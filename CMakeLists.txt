cmake_minimum_required(VERSION 3.19)
project(FastProto LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

FetchContent_Declare(robinhood
  GIT_REPOSITORY https://github.com/martinus/robin-hood-hashing.git
  GIT_TAG        3.11.5
)
FetchContent_MakeAvailable(robinhood)

FetchContent_Declare(boringssl
  GIT_REPOSITORY https://github.com/google/boringssl.git
  GIT_TAG        0.20250807.0
)
FetchContent_MakeAvailable(boringssl)

add_library(${PROJECT_NAME} STATIC
  src/crypto/crypto.cxx
  src/crypto/diffie_hellman.cxx
  src/net/common.cxx
  src/net/websocket_client.cxx
  src/net/websocket_server.cxx
  src/fast_proto/fast_proto.cxx
)
if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE
    /W4
    /permissive-
    $<$<CONFIG:Release>:/O2>
  )
else()
  target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    $<$<CONFIG:Release>:-O2>
  )
endif()
target_include_directories(${PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(${PROJECT_NAME} PRIVATE
  robin_hood::robin_hood
  crypto
  ssl
)

# tests

FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.17.0
)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(googlebench
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG        v1.9.4
)

FetchContent_MakeAvailable(googlebench)

add_executable(proto_tests tests/main.cxx)
target_link_libraries(proto_tests PRIVATE
  ${PROJECT_NAME}
  benchmark::benchmark
  gtest
  gtest_main
  robin_hood::robin_hood
)

# EXAMPLES
# echo
add_executable(example_echo_server examples/echo/server.cxx)
target_link_libraries(example_echo_server PRIVATE ${PROJECT_NAME} robin_hood::robin_hood)
add_executable(example_echo_client examples/echo/client.cxx)
target_link_libraries(example_echo_client PRIVATE ${PROJECT_NAME} robin_hood::robin_hood)

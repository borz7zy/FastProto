cmake_minimum_required(VERSION 3.19)
project(FastProto VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(cmake/fetch_library.cmake)
include(cmake/boost_asio.cmake)

if(POLICY CMP0069)
  cmake_policy(SET CMP0069 NEW)
endif()
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_err)
if(ipo_supported)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BORINGSSL_SKIP_TESTS ON CACHE BOOL "" FORCE)
set(BORINGSSL_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
fetch_library(boringssl
  https://github.com/google/boringssl.git
  0.20250807.0
)

add_boost(boost-1.89.0)

add_library(${PROJECT_NAME} STATIC
  src/crypto/crypto.cxx
  src/crypto/diffie_hellman.cxx
  src/net/common.cxx
  src/net/tcp_client.cxx
  src/net/tcp_server.cxx
  src/fast_proto/fast_proto.cxx
  src/logger/logger.cxx
)
if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE
    /W4
    /permissive-
    $<$<CONFIG:Debug>:/Od /Zi>
    $<$<CONFIG:Release>:/O2 /wd4701 /wd4703>
  )
else()
  target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    $<$<CONFIG:Debug>:-O0 -g>
    $<$<CONFIG:Release>:-O3>
  )
endif()
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
target_include_directories(${PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(${PROJECT_NAME} PRIVATE
  crypto
  ssl
  Boost::asio_core
)
if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)
endif()
if (ANDROID)
  target_link_libraries(${PROJECT_NAME} PRIVATE log)
endif()

# tests
if(FASTPROTO_BUILD_TESTING)
fetch_library(googletest
  https://github.com/google/googletest.git
  v1.17.0
)
fetch_library(googlebench
  https://github.com/google/benchmark.git
  v1.9.4
)

add_executable(proto_tests tests/main.cxx)
target_link_libraries(proto_tests PRIVATE
  ${PROJECT_NAME}
  benchmark::benchmark
  gtest
  gtest_main
)
endif()

# EXAMPLES
if(FASTPROTO_BUILD_EXAMPLES)
# echo
add_executable(example_echo_server examples/echo/server.cxx)
target_link_libraries(example_echo_server PRIVATE ${PROJECT_NAME})
add_executable(example_echo_client examples/echo/client.cxx)
target_link_libraries(example_echo_client PRIVATE ${PROJECT_NAME})
endif()

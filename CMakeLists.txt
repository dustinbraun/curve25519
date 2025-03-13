cmake_minimum_required(VERSION 3.23)

project(x25519_lite)

add_library(x25519_lite)

target_include_directories(x25519_lite PUBLIC include)

target_compile_features(x25519_lite PRIVATE cxx_std_17)

add_subdirectory(examples)
add_subdirectory(src)

enable_testing()
add_subdirectory(tests)
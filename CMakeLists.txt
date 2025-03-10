cmake_minimum_required(VERSION 3.23)

project(curve25519)

add_library(curve25519)

target_include_directories(curve25519 PUBLIC include)

target_compile_features(curve25519 PRIVATE cxx_std_17)

add_subdirectory(examples)
add_subdirectory(src)

enable_testing()
add_subdirectory(tests)
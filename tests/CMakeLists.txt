Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.4.0 # or a later release
)

FetchContent_MakeAvailable(Catch2)

add_executable(test_cases)

target_compile_features(test_cases
    PRIVATE cxx_std_17
)

target_sources(test_cases
    PRIVATE test_cases.cpp
)

target_link_libraries(test_cases
    PRIVATE curve25519
    PRIVATE Catch2::Catch2WithMain
)

add_test(NAME test_cases COMMAND test_cases)

add_executable(example)

target_sources(example
    PRIVATE example.cpp
)

target_compile_features(example
    PRIVATE cxx_std_17
)

target_link_libraries(example
    PRIVATE curve25519
)

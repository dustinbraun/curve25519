#pragma once

#include <array>

namespace x25519_lite {
    
void generate_keys(
    uint8_t* sec_key_bytes,
    uint8_t* pub_key_bytes
) noexcept;

// ToDo: Experimental API
inline
std::pair<std::array<std::uint8_t, 32>, std::array<uint8_t, 32>>
generate_keys() noexcept {
    std::array<uint8_t, 32> sec_key;
    std::array<uint8_t, 32> pub_key;
    generate_keys(sec_key.data(), pub_key.data());
    return { sec_key, pub_key };
}

void x25519(const uint8_t * base_bytes, const uint8_t * exponent_bytes, uint8_t* result_bytes) noexcept;

inline
std::array<uint8_t, 32>
x25519(
    const std::array<uint8_t, 32> & base, // their pub. key
    const std::array<uint8_t, 32> & exponent // my pri. key
) noexcept {
    std::array<uint8_t, 32> result;
    x25519(base.data(), exponent.data(), result.data());
    return result;
}

} // namespace x25519_lite

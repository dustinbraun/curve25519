#include <x25519_lite/detail/field_element.hpp>
#include <x25519_lite/detail/point.hpp>
#include <x25519_lite/x25519.hpp>

namespace x25519_lite {

// ToDo: Provide a strategy-class to provide user-defined (secure) random generation.
void generate_keys(
    uint8_t* sec_key_bytes,
    uint8_t* pub_key_bytes
) noexcept {
    for (size_t i = 0; i < 32; ++i) {
        sec_key_bytes[i] = (uint8_t)std::rand();
    }
    detail::Point base = detail::FE_G_X;
    detail::FieldElement exponent(sec_key_bytes);
    exponent.clamp_exponent();
    detail::Point pub_key = base * exponent;
    pub_key.get_x().to_bytes(pub_key_bytes);
}

void
diffie_hellman(
    const uint8_t * base_bytes,
    const uint8_t * exponent_bytes,
    uint8_t* result_bytes
) noexcept {
    detail::Point base(base_bytes);
    base.get_x().clamp_base();
    
    detail::FieldElement exponent(exponent_bytes);
    exponent.clamp_exponent();

    auto secret = base * exponent;
    
    secret.get_x().to_bytes(result_bytes);
}

} // namespace x25519_lite
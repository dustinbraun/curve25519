#pragma once

#include "common.hpp"

namespace x25519_lite {

namespace detail {

// This class provided 256-bit unsigned integer modulus P operations.
class FieldElement {
public:
    constexpr
    FieldElement(
        uint32_t limb0,
        uint32_t limb1,
        uint32_t limb2,
        uint32_t limb3,
        uint32_t limb4,
        uint32_t limb5,
        uint32_t limb6,
        uint32_t limb7
    ) noexcept : m_limbs({ limb0, limb1, limb2, limb3, limb4, limb5, limb6, limb7 }) {

    }

    FieldElement(
        const uint8_t *bytes
    ) noexcept;

    bool
    operator == (
        const FieldElement& rhs
    ) const noexcept;

    bool
    operator >= (
        const FieldElement & rhs
    ) const noexcept;

    FieldElement
    operator + (
        const FieldElement& rhs
    ) const noexcept;

    FieldElement
    operator - (
        const FieldElement& rhs
    ) const noexcept;

    FieldElement
    operator * (
        const FieldElement& rhs
    ) const noexcept;

    void
    to_bytes(
        uint8_t *bytes
    ) const noexcept;

    void
    clamp_base() noexcept;
    
    void
    clamp_exponent() noexcept;

    bool
    is_mod_p(
    ) const noexcept;

    FieldElement
    to_mod_p(
    ) noexcept;

    FieldElement
    add(
        const FieldElement & rhs
    ) const noexcept {
        return (*this) + rhs;
    }

    FieldElement
    sub(
        const FieldElement & rhs
    ) const noexcept {
        return (*this) - rhs;
    }

    FieldElement
    mul(
        const FieldElement & rhs
    ) const noexcept {
        return (*this) * rhs;
    }

    FieldElement
    pow(
        const FieldElement & rhs
    ) const noexcept;

    FieldElement
    square(
    ) const noexcept;

    FieldElement
    inverse(
    ) const noexcept;

    bool
    get_bit(
        size_t index
    ) const noexcept {
        assert(index < 256);
        return ((m_limbs[index/32] >> (index % 32)) & 1) != 0;
    }

private:
    std::array<uint32_t, 8> m_limbs;


    // ToDo: Use std::pair to return sum and carry.
    FieldElement
    overflowing_add(
        const FieldElement &rhs,
        uint32_t &carry
    ) const noexcept;

    // ToDo: Use std::pair to return dif and borrow.
    FieldElement
    borrowing_sub(
        const FieldElement &rhs,
        uint32_t &borrow
    ) const noexcept;

    FieldElement
    wrapping_add_p(
    ) const noexcept;

    FieldElement
    wrapping_sub_p(
    ) const noexcept;
};

constexpr FieldElement FE_0 = FieldElement(
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
);

constexpr FieldElement FE_1 = FieldElement(
    0x00000001,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
);

constexpr FieldElement FE_2 = FieldElement(
    0x00000002,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
);

constexpr FieldElement FE_P = FieldElement(
    0xFFFFFFED,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFF
);

constexpr FieldElement FE_P_MINUS_1 = FieldElement(
    0xFFFFFFEC,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFF
);

constexpr FieldElement FE_P_MINUS_2 = FieldElement(
    0xFFFFFFEB,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x7FFFFFFF
);

constexpr FieldElement FE_121665 = FieldElement(
    121665,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
);

constexpr FieldElement FE_G_X = FieldElement(
    0x00000009,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
);

} // namespace detail
} // namespace x25519_lite

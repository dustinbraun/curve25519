#pragma once

#include "common.hpp"
#include "field_element.hpp"

namespace x25519_lite {

class Point {
public:
    CURVE25519_INLINE
    Point(
        const FieldElement& x
    ) noexcept : m_x(x) {

    }

    CURVE25519_INLINE
    Point(
        const uint8_t* x_bytes
    ) noexcept : m_x(x_bytes) {

    }

    CURVE25519_INLINE
    Point
    operator * (
        const FieldElement & rhs
    ) {
        return mul(rhs);
    }

    CURVE25519_INLINE
    const FieldElement &
    get_x(
    ) const noexcept {
        return m_x;
    }

    CURVE25519_INLINE
    FieldElement &
    get_x(
    ) noexcept {
        return m_x;
    }

    Point mul(const FieldElement& rhs) const noexcept;

private:
    FieldElement m_x;
};

} // namespace x25519_lite

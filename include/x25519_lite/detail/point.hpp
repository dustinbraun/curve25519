#pragma once

#include "common.hpp"
#include "field_element.hpp"

namespace x25519_lite {

namespace detail {

class Point {
public:
    Point(const FieldElement& x) noexcept : m_x(x) {

    }

    Point(const uint8_t* x_bytes) noexcept : m_x(x_bytes) {

    }

    Point operator * (const FieldElement & rhs) const noexcept;

    const FieldElement & get_x() const noexcept {
        return m_x;
    }

    FieldElement & get_x() noexcept {
        return m_x;
    }

private:
    FieldElement m_x;
};

} // namespace detail
} // namespace x25519_lite

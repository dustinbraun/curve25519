#include <tuple>

#include <x25519_lite/detail/point.hpp>

namespace x25519_lite {

namespace detail {

namespace {

std::pair<FieldElement, FieldElement>
conditional_swap(
    const FieldElement& a,
    const FieldElement& b,
    uint32_t condition
) noexcept {
    if (condition != 0) {
        return { b, a };
    }
    else {
        return { a, b };
    }
}

} // anon. namespace

Point
Point::operator * (
    const FieldElement& rhs
) const noexcept {
    // Montgomery Ladder from IRTF RFC 7748.

    auto x_1 = m_x;
    auto x_2 = FE_1;
    auto z_2 = FE_0;
    auto x_3 = m_x;
    auto z_3 = FE_1;

    uint32_t swap_condition = 0;

    for (int i = 254; i >= 0; --i) { // 254 because bit 255 is always 0
        uint32_t k_t = (uint32_t)rhs.get_bit(i);
        swap_condition ^= k_t;
        auto [x_2a, x_3a] = conditional_swap(x_2, x_3, swap_condition);
        auto [z_2a, z_3a] = conditional_swap(z_2, z_3, swap_condition);
        swap_condition = k_t;
        auto a = x_2a + z_2a;
        auto aa = a.square();
        auto b = x_2a - z_2a;
        auto bb = b.square();
        auto e = aa - bb;
        auto c = x_3a + z_3a;
        auto d = x_3a - z_3a;
        auto da = d * a;
        auto cb = c * b;
        auto x_3b = (da + cb).square();
        auto z_3b = x_1 * (da - cb).square();
        auto x_2b = aa * bb;
        auto z_2b = e * (aa + (FE_121665 * e));
        x_2 = x_2b;
        x_3 = x_3b;
        z_2 = z_2b;
        z_3 = z_3b;
    }

    std::tie(x_2, std::ignore) = conditional_swap(x_2, x_3, swap_condition);
    std::tie(z_2, std::ignore) = conditional_swap(z_2, z_3, swap_condition);

    return Point(x_2 * z_2.inverse());
}

} // namespace detail
} // namespace x25519_lite

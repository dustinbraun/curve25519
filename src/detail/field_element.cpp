#include <tuple>

#include <x25519_lite/detail/field_element.hpp>

namespace x25519_lite {

namespace {

// ToDo: Use std::pair to return sum and carry.
uint32_t
adc(
    uint32_t a,
    uint32_t b,
    uint32_t &carry
) noexcept {
    uint64_t sum = (uint64_t)a + (uint64_t)b + (uint64_t)carry;
    carry = sum >> 32;
    return (uint32_t)sum;
}

// ToDo: Use std::pair to return dif and borrow.
uint32_t
sbb(
    uint32_t a,
    uint32_t b,
    uint32_t &borrow
) noexcept {
    uint64_t res = (uint64_t)a - ((uint64_t)b + (uint64_t)(borrow >> 31));
    borrow = res >> 32;
    return (uint32_t)res;
}

std::pair<uint32_t, uint32_t>
mac(
    uint32_t a,
    uint32_t b,
    uint32_t c,
    uint32_t carry
) noexcept {
    uint64_t res = (uint64_t)a + (uint64_t)b * (uint64_t)c + (uint64_t)carry;
    carry = res >> 32;
    return { (uint32_t)res, (uint32_t)carry };
}

// ToDo: Unroll for-loop.
void
reduce_carry(
    uint64_t* limbs
) noexcept {
    for (size_t i = 0; i < 7; ++i) {
        uint64_t carry = limbs[i] >> 32;
        limbs[i] -= carry << 32;
        limbs[i + 1] += carry;
    }
    uint64_t carry = limbs[7] >> 32;
    limbs[7] -= carry << 32;
    limbs[0] += carry * 38;
}

} // anon. namespace

namespace detail {

FieldElement::FieldElement(const uint8_t *bytes) noexcept {
    assert(bytes);
    m_limbs[0] = (uint32_t)bytes[ 0] | ((uint32_t)bytes[ 1] << 8) | ((uint32_t)bytes[ 2] << 16) | ((uint32_t)bytes[ 3] << 24);
    m_limbs[1] = (uint32_t)bytes[ 4] | ((uint32_t)bytes[ 5] << 8) | ((uint32_t)bytes[ 6] << 16) | ((uint32_t)bytes[ 7] << 24);
    m_limbs[2] = (uint32_t)bytes[ 8] | ((uint32_t)bytes[ 9] << 8) | ((uint32_t)bytes[10] << 16) | ((uint32_t)bytes[11] << 24);
    m_limbs[3] = (uint32_t)bytes[12] | ((uint32_t)bytes[13] << 8) | ((uint32_t)bytes[14] << 16) | ((uint32_t)bytes[15] << 24);
    m_limbs[4] = (uint32_t)bytes[16] | ((uint32_t)bytes[17] << 8) | ((uint32_t)bytes[18] << 16) | ((uint32_t)bytes[19] << 24);
    m_limbs[5] = (uint32_t)bytes[20] | ((uint32_t)bytes[21] << 8) | ((uint32_t)bytes[22] << 16) | ((uint32_t)bytes[23] << 24);
    m_limbs[6] = (uint32_t)bytes[24] | ((uint32_t)bytes[25] << 8) | ((uint32_t)bytes[26] << 16) | ((uint32_t)bytes[27] << 24);
    m_limbs[7] = (uint32_t)bytes[28] | ((uint32_t)bytes[29] << 8) | ((uint32_t)bytes[30] << 16) | ((uint32_t)bytes[31] << 24);
}

bool FieldElement::operator == (const FieldElement& rhs) const noexcept {
    if (m_limbs[0] != rhs.m_limbs[0]) { return false; }
    if (m_limbs[1] != rhs.m_limbs[1]) { return false; }
    if (m_limbs[2] != rhs.m_limbs[2]) { return false; }
    if (m_limbs[3] != rhs.m_limbs[3]) { return false; }
    if (m_limbs[4] != rhs.m_limbs[4]) { return false; }
    if (m_limbs[5] != rhs.m_limbs[5]) { return false; }
    if (m_limbs[6] != rhs.m_limbs[6]) { return false; }
    if (m_limbs[7] != rhs.m_limbs[7]) { return false; }
    return true;
}

bool FieldElement::operator >= (const FieldElement & rhs) const noexcept {
    if (m_limbs[7] > rhs.m_limbs[7]) { return true; } else if (m_limbs[7] < rhs.m_limbs[7]) { return false; }
    if (m_limbs[6] > rhs.m_limbs[6]) { return true; } else if (m_limbs[6] < rhs.m_limbs[6]) { return false; }
    if (m_limbs[5] > rhs.m_limbs[5]) { return true; } else if (m_limbs[5] < rhs.m_limbs[5]) { return false; }
    if (m_limbs[4] > rhs.m_limbs[4]) { return true; } else if (m_limbs[4] < rhs.m_limbs[4]) { return false; }
    if (m_limbs[3] > rhs.m_limbs[3]) { return true; } else if (m_limbs[3] < rhs.m_limbs[3]) { return false; }
    if (m_limbs[2] > rhs.m_limbs[2]) { return true; } else if (m_limbs[2] < rhs.m_limbs[2]) { return false; }
    if (m_limbs[1] > rhs.m_limbs[1]) { return true; } else if (m_limbs[1] < rhs.m_limbs[1]) { return false; }
    if (m_limbs[0] > rhs.m_limbs[0]) { return true; } else if (m_limbs[0] < rhs.m_limbs[0]) { return false; }
    return true;
}

FieldElement
FieldElement::operator + (
    const FieldElement& rhs
) const noexcept {
    uint32_t carry = 0;
    FieldElement res = overflowing_add(rhs, carry);
    if ((carry != 0) || !res.is_mod_p()) {
        res = res.wrapping_sub_p();
    }
    return res;
}

FieldElement
FieldElement::operator - (
    const FieldElement& rhs
) const noexcept {
    uint32_t borrow = 0;
    auto fe = borrowing_sub(rhs, borrow);
    if (borrow != 0)
    {
        fe = fe.wrapping_add_p();
    }
    return fe;
}

FieldElement
FieldElement::operator * (
    const FieldElement& rhs
) const noexcept {
    uint32_t prods[16] = {};

    uint32_t carry = 0;

    std::tie(prods[ 0],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[0],     0);
    std::tie(prods[ 1],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[1], carry);
    std::tie(prods[ 2],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[2], carry);
    std::tie(prods[ 3],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[3], carry);
    std::tie(prods[ 4],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[4], carry);
    std::tie(prods[ 5],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[5], carry);
    std::tie(prods[ 6],     carry) = mac(        0, m_limbs[0], rhs.m_limbs[6], carry);
    std::tie(prods[ 7], prods[ 8]) = mac(        0, m_limbs[0], rhs.m_limbs[7], carry);
    std::tie(prods[ 1],     carry) = mac(prods[ 1], m_limbs[1], rhs.m_limbs[0],     0);
    std::tie(prods[ 2],     carry) = mac(prods[ 2], m_limbs[1], rhs.m_limbs[1], carry);
    std::tie(prods[ 3],     carry) = mac(prods[ 3], m_limbs[1], rhs.m_limbs[2], carry);
    std::tie(prods[ 4],     carry) = mac(prods[ 4], m_limbs[1], rhs.m_limbs[3], carry);
    std::tie(prods[ 5],     carry) = mac(prods[ 5], m_limbs[1], rhs.m_limbs[4], carry);
    std::tie(prods[ 6],     carry) = mac(prods[ 6], m_limbs[1], rhs.m_limbs[5], carry);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[1], rhs.m_limbs[6], carry);
    std::tie(prods[ 8], prods[ 9]) = mac(prods[ 8], m_limbs[1], rhs.m_limbs[7], carry);
    std::tie(prods[ 2],     carry) = mac(prods[ 2], m_limbs[2], rhs.m_limbs[0],     0);
    std::tie(prods[ 3],     carry) = mac(prods[ 3], m_limbs[2], rhs.m_limbs[1], carry);
    std::tie(prods[ 4],     carry) = mac(prods[ 4], m_limbs[2], rhs.m_limbs[2], carry);
    std::tie(prods[ 5],     carry) = mac(prods[ 5], m_limbs[2], rhs.m_limbs[3], carry);
    std::tie(prods[ 6],     carry) = mac(prods[ 6], m_limbs[2], rhs.m_limbs[4], carry);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[2], rhs.m_limbs[5], carry);
    std::tie(prods[ 8],     carry) = mac(prods[ 8], m_limbs[2], rhs.m_limbs[6], carry);
    std::tie(prods[ 9], prods[10]) = mac(prods[ 9], m_limbs[2], rhs.m_limbs[7], carry);
    std::tie(prods[ 3],     carry) = mac(prods[ 3], m_limbs[3], rhs.m_limbs[0],     0);
    std::tie(prods[ 4],     carry) = mac(prods[ 4], m_limbs[3], rhs.m_limbs[1], carry);
    std::tie(prods[ 5],     carry) = mac(prods[ 5], m_limbs[3], rhs.m_limbs[2], carry);
    std::tie(prods[ 6],     carry) = mac(prods[ 6], m_limbs[3], rhs.m_limbs[3], carry);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[3], rhs.m_limbs[4], carry);
    std::tie(prods[ 8],     carry) = mac(prods[ 8], m_limbs[3], rhs.m_limbs[5], carry);
    std::tie(prods[ 9],     carry) = mac(prods[ 9], m_limbs[3], rhs.m_limbs[6], carry);
    std::tie(prods[10], prods[11]) = mac(prods[10], m_limbs[3], rhs.m_limbs[7], carry);
    std::tie(prods[ 4],     carry) = mac(prods[ 4], m_limbs[4], rhs.m_limbs[0],     0);
    std::tie(prods[ 5],     carry) = mac(prods[ 5], m_limbs[4], rhs.m_limbs[1], carry);
    std::tie(prods[ 6],     carry) = mac(prods[ 6], m_limbs[4], rhs.m_limbs[2], carry);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[4], rhs.m_limbs[3], carry);
    std::tie(prods[ 8],     carry) = mac(prods[ 8], m_limbs[4], rhs.m_limbs[4], carry);
    std::tie(prods[ 9],     carry) = mac(prods[ 9], m_limbs[4], rhs.m_limbs[5], carry);
    std::tie(prods[10],     carry) = mac(prods[10], m_limbs[4], rhs.m_limbs[6], carry);
    std::tie(prods[11], prods[12]) = mac(prods[11], m_limbs[4], rhs.m_limbs[7], carry);
    std::tie(prods[ 5],     carry) = mac(prods[ 5], m_limbs[5], rhs.m_limbs[0],     0);
    std::tie(prods[ 6],     carry) = mac(prods[ 6], m_limbs[5], rhs.m_limbs[1], carry);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[5], rhs.m_limbs[2], carry);
    std::tie(prods[ 8],     carry) = mac(prods[ 8], m_limbs[5], rhs.m_limbs[3], carry);
    std::tie(prods[ 9],     carry) = mac(prods[ 9], m_limbs[5], rhs.m_limbs[4], carry);
    std::tie(prods[10],     carry) = mac(prods[10], m_limbs[5], rhs.m_limbs[5], carry);
    std::tie(prods[11],     carry) = mac(prods[11], m_limbs[5], rhs.m_limbs[6], carry);
    std::tie(prods[12], prods[13]) = mac(prods[12], m_limbs[5], rhs.m_limbs[7], carry);
    std::tie(prods[ 6],     carry) = mac(prods[ 6], m_limbs[6], rhs.m_limbs[0],     0);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[6], rhs.m_limbs[1], carry);
    std::tie(prods[ 8],     carry) = mac(prods[ 8], m_limbs[6], rhs.m_limbs[2], carry);
    std::tie(prods[ 9],     carry) = mac(prods[ 9], m_limbs[6], rhs.m_limbs[3], carry);
    std::tie(prods[10],     carry) = mac(prods[10], m_limbs[6], rhs.m_limbs[4], carry);
    std::tie(prods[11],     carry) = mac(prods[11], m_limbs[6], rhs.m_limbs[5], carry);
    std::tie(prods[12],     carry) = mac(prods[12], m_limbs[6], rhs.m_limbs[6], carry);
    std::tie(prods[13], prods[14]) = mac(prods[13], m_limbs[6], rhs.m_limbs[7], carry);
    std::tie(prods[ 7],     carry) = mac(prods[ 7], m_limbs[7], rhs.m_limbs[0],     0);
    std::tie(prods[ 8],     carry) = mac(prods[ 8], m_limbs[7], rhs.m_limbs[1], carry);
    std::tie(prods[ 9],     carry) = mac(prods[ 9], m_limbs[7], rhs.m_limbs[2], carry);
    std::tie(prods[10],     carry) = mac(prods[10], m_limbs[7], rhs.m_limbs[3], carry);
    std::tie(prods[11],     carry) = mac(prods[11], m_limbs[7], rhs.m_limbs[4], carry);
    std::tie(prods[12],     carry) = mac(prods[12], m_limbs[7], rhs.m_limbs[5], carry);
    std::tie(prods[13],     carry) = mac(prods[13], m_limbs[7], rhs.m_limbs[6], carry);
    std::tie(prods[14], prods[15]) = mac(prods[14], m_limbs[7], rhs.m_limbs[7], carry);

    uint64_t wide_limbs[8] = {
        (uint64_t)prods[0] + (uint64_t)prods[ 8] * 38,
        (uint64_t)prods[1] + (uint64_t)prods[ 9] * 38,
        (uint64_t)prods[2] + (uint64_t)prods[10] * 38,
        (uint64_t)prods[3] + (uint64_t)prods[11] * 38,
        (uint64_t)prods[4] + (uint64_t)prods[12] * 38,
        (uint64_t)prods[5] + (uint64_t)prods[13] * 38,
        (uint64_t)prods[6] + (uint64_t)prods[14] * 38,
        (uint64_t)prods[7] + (uint64_t)prods[15] * 38,
    };

    reduce_carry(wide_limbs);
    reduce_carry(wide_limbs);
    reduce_carry(wide_limbs);

    assert(wide_limbs[0] <= UINT32_MAX);
    assert(wide_limbs[1] <= UINT32_MAX);
    assert(wide_limbs[2] <= UINT32_MAX);
    assert(wide_limbs[3] <= UINT32_MAX);
    assert(wide_limbs[4] <= UINT32_MAX);
    assert(wide_limbs[5] <= UINT32_MAX);
    assert(wide_limbs[6] <= UINT32_MAX);
    assert(wide_limbs[7] <= UINT32_MAX);

    FieldElement res(
        (uint32_t)wide_limbs[0],
        (uint32_t)wide_limbs[1],
        (uint32_t)wide_limbs[2],
        (uint32_t)wide_limbs[3],
        (uint32_t)wide_limbs[4],
        (uint32_t)wide_limbs[5],
        (uint32_t)wide_limbs[6],
        (uint32_t)wide_limbs[7]
    );

    auto res_mod_p = res.to_mod_p();

    return res_mod_p;
}

void
FieldElement::clamp_base() noexcept {
    m_limbs[7] &= 0b01111111111111111111111111111111;
}

void
FieldElement::clamp_exponent() noexcept {
    m_limbs[0] &= 0b11111111111111111111111111111000;
    m_limbs[7] &= 0b01111111111111111111111111111111;
    m_limbs[7] |= 0b01000000000000000000000000000000;
}

void FieldElement::to_bytes(uint8_t *bytes) const noexcept {
    assert(bytes);
    bytes[ 0] = (uint8_t)(m_limbs[0]      );
    bytes[ 1] = (uint8_t)(m_limbs[0] >>  8);
    bytes[ 2] = (uint8_t)(m_limbs[0] >> 16);
    bytes[ 3] = (uint8_t)(m_limbs[0] >> 24);
    bytes[ 4] = (uint8_t)(m_limbs[1]      );
    bytes[ 5] = (uint8_t)(m_limbs[1] >>  8);
    bytes[ 6] = (uint8_t)(m_limbs[1] >> 16);
    bytes[ 7] = (uint8_t)(m_limbs[1] >> 24);
    bytes[ 8] = (uint8_t)(m_limbs[2]      );
    bytes[ 9] = (uint8_t)(m_limbs[2] >>  8);
    bytes[10] = (uint8_t)(m_limbs[2] >> 16);
    bytes[11] = (uint8_t)(m_limbs[2] >> 24);
    bytes[12] = (uint8_t)(m_limbs[3]      );
    bytes[13] = (uint8_t)(m_limbs[3] >>  8);
    bytes[14] = (uint8_t)(m_limbs[3] >> 16);
    bytes[15] = (uint8_t)(m_limbs[3] >> 24);
    bytes[16] = (uint8_t)(m_limbs[4]      );
    bytes[17] = (uint8_t)(m_limbs[4] >>  8);
    bytes[18] = (uint8_t)(m_limbs[4] >> 16);
    bytes[19] = (uint8_t)(m_limbs[4] >> 24);
    bytes[20] = (uint8_t)(m_limbs[5]      );
    bytes[21] = (uint8_t)(m_limbs[5] >> 8);
    bytes[22] = (uint8_t)(m_limbs[5] >> 16);
    bytes[23] = (uint8_t)(m_limbs[5] >> 24);
    bytes[24] = (uint8_t)(m_limbs[6]      );
    bytes[25] = (uint8_t)(m_limbs[6] >>  8);
    bytes[26] = (uint8_t)(m_limbs[6] >> 16);
    bytes[27] = (uint8_t)(m_limbs[6] >> 24);
    bytes[28] = (uint8_t)(m_limbs[7]      );
    bytes[29] = (uint8_t)(m_limbs[7] >>  8);
    bytes[30] = (uint8_t)(m_limbs[7] >> 16);
    bytes[31] = (uint8_t)(m_limbs[7] >> 24);
}

bool FieldElement::is_mod_p() const noexcept {
    if ((*this) >= FE_P) {
        return false;
    }
    return true;
}

FieldElement FieldElement::to_mod_p() noexcept {
    FieldElement res = (*this);
    while (!res.is_mod_p()) {
        res = res.wrapping_sub_p();
    }
    return res;
}

FieldElement FieldElement::pow(const FieldElement & exponent) const noexcept {
    auto res = FE_1;
    auto base = (*this);
    for (size_t i = 0; i < 255; ++i) {
        if (exponent.get_bit(i)) {
            res = res * base;
        }
        base = base.square();
    }
    return res;
}

FieldElement
FieldElement::square(
) const noexcept {
    return (*this) * (*this);
}

FieldElement
FieldElement::inverse(
) const noexcept {
    return pow(FE_P_MINUS_2);
}

FieldElement FieldElement::overflowing_add(const FieldElement &rhs, uint32_t &carry) const noexcept {
    carry = 0;
    uint32_t limbs[8] = {};
    limbs[0] = adc(m_limbs[0], rhs.m_limbs[0], carry);
    limbs[1] = adc(m_limbs[1], rhs.m_limbs[1], carry);
    limbs[2] = adc(m_limbs[2], rhs.m_limbs[2], carry);
    limbs[3] = adc(m_limbs[3], rhs.m_limbs[3], carry);
    limbs[4] = adc(m_limbs[4], rhs.m_limbs[4], carry);
    limbs[5] = adc(m_limbs[5], rhs.m_limbs[5], carry);
    limbs[6] = adc(m_limbs[6], rhs.m_limbs[6], carry);
    limbs[7] = adc(m_limbs[7], rhs.m_limbs[7], carry);
    return FieldElement(
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
        limbs[4],
        limbs[5],
        limbs[6],
        limbs[7]
    );
}

FieldElement FieldElement::borrowing_sub(const FieldElement &rhs, uint32_t &borrow) const noexcept {
    borrow = 0;
    uint32_t limbs[8] = {};
    limbs[0] = sbb(m_limbs[0], rhs.m_limbs[0], borrow);
    limbs[1] = sbb(m_limbs[1], rhs.m_limbs[1], borrow);
    limbs[2] = sbb(m_limbs[2], rhs.m_limbs[2], borrow);
    limbs[3] = sbb(m_limbs[3], rhs.m_limbs[3], borrow);
    limbs[4] = sbb(m_limbs[4], rhs.m_limbs[4], borrow);
    limbs[5] = sbb(m_limbs[5], rhs.m_limbs[5], borrow);
    limbs[6] = sbb(m_limbs[6], rhs.m_limbs[6], borrow);
    limbs[7] = sbb(m_limbs[7], rhs.m_limbs[7], borrow);
    return FieldElement(
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
        limbs[4],
        limbs[5],
        limbs[6],
        limbs[7]
    );
}

FieldElement FieldElement::wrapping_add_p() const noexcept {
    uint32_t carry = 0;
    uint32_t limbs[8];
    limbs[0] = adc(m_limbs[0], FE_P.m_limbs[0], carry);
    limbs[1] = adc(m_limbs[1], FE_P.m_limbs[1], carry);
    limbs[2] = adc(m_limbs[2], FE_P.m_limbs[2], carry);
    limbs[3] = adc(m_limbs[3], FE_P.m_limbs[3], carry);
    limbs[4] = adc(m_limbs[4], FE_P.m_limbs[4], carry);
    limbs[5] = adc(m_limbs[5], FE_P.m_limbs[5], carry);
    limbs[6] = adc(m_limbs[6], FE_P.m_limbs[6], carry);
    limbs[7] = adc(m_limbs[7], FE_P.m_limbs[7], carry);
    return FieldElement(
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
        limbs[4],
        limbs[5],
        limbs[6],
        limbs[7]
    );
}

FieldElement FieldElement::wrapping_sub_p() const noexcept {
    uint32_t borrow = 0;
    uint32_t limbs[8] = {};
    limbs[0] = sbb(m_limbs[0], FE_P.m_limbs[0], borrow);
    limbs[1] = sbb(m_limbs[1], FE_P.m_limbs[1], borrow);
    limbs[2] = sbb(m_limbs[2], FE_P.m_limbs[2], borrow);
    limbs[3] = sbb(m_limbs[3], FE_P.m_limbs[3], borrow);
    limbs[4] = sbb(m_limbs[4], FE_P.m_limbs[4], borrow);
    limbs[5] = sbb(m_limbs[5], FE_P.m_limbs[5], borrow);
    limbs[6] = sbb(m_limbs[6], FE_P.m_limbs[6], borrow);
    limbs[7] = sbb(m_limbs[7], FE_P.m_limbs[7], borrow);
    return FieldElement(
        limbs[0],
        limbs[1],
        limbs[2],
        limbs[3],
        limbs[4],
        limbs[5],
        limbs[6],
        limbs[7]
    );
}

} // namespace detail
} // namespace x25519_lite

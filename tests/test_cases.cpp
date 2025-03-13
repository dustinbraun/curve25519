#include <catch2/catch_test_macros.hpp>

#include <x25519_lite/x25519.hpp>
#include <x25519_lite/detail/field_element.hpp>
#include <x25519_lite/detail/point.hpp>

TEST_CASE("rfc7748_0", "[Point]") {
    using namespace x25519_lite;

    constexpr std::array<uint8_t, 32> BASE_BYTES = {
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
        0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
        0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
        0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
    };
    constexpr std::array<uint8_t, 32> EXPONENT_BYTES = {
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
        0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
        0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
        0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
    };
    constexpr std::array<uint8_t, 32> EXPECTED_RESULT_BYTES = {
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
        0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
        0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
        0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
    };
    
    std::array<uint8_t, 32> result_bytes = {};

    x25519(BASE_BYTES.data(), EXPONENT_BYTES.data(), result_bytes.data());

    REQUIRE(result_bytes == EXPECTED_RESULT_BYTES);
}

TEST_CASE("rfc7748_1", "[Point]") {
    using namespace x25519_lite;

    std::array<uint8_t, 32> u = {
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    std::array<uint8_t, 32> k = {
        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    std::array<uint8_t, 32> r = {};

    x25519(u.data(), k.data(), r.data());

    u = k;
    k = r;

    REQUIRE(k == std::array<uint8_t, 32>({
        0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
        0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
        0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
        0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79,
    }));

    for (size_t i = 1; i < 1000; ++i) {
        x25519(u.data(), k.data(), r.data());
        u = k;
        k = r;
    }

    REQUIRE(k == std::array<uint8_t, 32>({
        0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
        0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
        0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
        0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51,
    }));

    /*

    for (size_t i = 1000; i < 1000000; ++i) {
        x25519(u.data(), k.data(), r.data());
        u = k;
        k = r;
    }

    REQUIRE(k == std::array<uint8_t, 32>({
        0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
        0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
        0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
        0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24,
    }));

    */
}

TEST_CASE("from-and-to bytes", "[FieldElement]") {
    constexpr uint8_t BYTES[32] = {
        0x23, 0x57, 0x48, 0x29,
        0x44, 0x32, 0x32, 0x95,
        0x34, 0x48, 0x38, 0x49,
        0x34, 0x57, 0x48, 0x19,
        0x31, 0x56, 0x34, 0x45,
        0x22, 0x43, 0x56, 0x54,
        0x34, 0x52, 0x22, 0x53,
        0x04, 0x63, 0x84, 0x23,
    };

    uint8_t res_bytes[32];

    x25519_lite::FieldElement fe(BYTES);
    fe.to_bytes(res_bytes);

    REQUIRE(std::memcmp(BYTES, res_bytes, 32) == 0);
}

TEST_CASE("add edge-cases", "[FieldElement]") {
    using namespace x25519_lite;
     
    REQUIRE((FE_0 + FE_0) == FE_0);
    REQUIRE((FE_0 + FE_1) == FE_1);
    REQUIRE((FE_1 + FE_0) == FE_1);
    REQUIRE((FE_1 + FE_1) == FE_2);

    REQUIRE((FE_P_MINUS_1 + FE_1) == FE_0);
    REQUIRE((FE_P_MINUS_2 + FE_2) == FE_0);

    REQUIRE((FE_P_MINUS_2 + FE_1) == FE_P_MINUS_1);
}

TEST_CASE("sub edge-cases", "[FieldElement]") {
    using namespace x25519_lite;

    REQUIRE((FE_0 - FE_0) == FE_0);
    REQUIRE((FE_0 - FE_1) == FE_P_MINUS_1);
    REQUIRE((FE_0 - FE_2) == FE_P_MINUS_2);
}

TEST_CASE("mul edge-cases", "[FieldElement]") {
    using namespace x25519_lite;

    REQUIRE((FE_0 * FE_0) == FE_0);
    REQUIRE((FE_0 * FE_1) == FE_0);
    REQUIRE((FE_1 * FE_0) == FE_0);
    REQUIRE((FE_1 * FE_1) == FE_1);

    REQUIRE((FE_P_MINUS_1 * FE_0) == FE_0);
    REQUIRE((FE_0 * FE_P_MINUS_1) == FE_0);

    REQUIRE((FE_P_MINUS_1 * FE_1) == FE_P_MINUS_1);
    REQUIRE((FE_1 * FE_P_MINUS_1) == FE_P_MINUS_1);
}

TEST_CASE("mul", "[FieldElement]") {
    using namespace x25519_lite;

    constexpr uint8_t LHS_BYTES[32] = {
        0x23, 0x57, 0x48, 0x29,
        0x44, 0x32, 0x32, 0x95,
        0x34, 0x48, 0x38, 0x49,
        0x34, 0x57, 0x48, 0x19,
        0x31, 0x56, 0x34, 0x45,
        0x22, 0x43, 0x56, 0x54,
        0x34, 0x52, 0x22, 0x53,
        0x04, 0x63, 0x84, 0x23,
    };

    constexpr uint8_t RHS_BYTES[32] = {
        0x62, 0x54, 0x21, 0x32,
        0x42, 0x63, 0x44, 0x23,
        0x24, 0x33, 0x52, 0x66,
        0x55, 0x48, 0x85, 0x43,
        0x64, 0x25, 0x32, 0x23,
        0x52, 0x23, 0x52, 0x23,
        0x55, 0x34, 0x65, 0x32,
        0x93, 0x56, 0x23, 0x63,
    };

    constexpr uint8_t EXPECTED_PRODUCT_BYTES[32] = {
        0x64, 0x3a, 0x43, 0x6b,
        0xa9, 0x0f, 0x7a, 0xa2,
        0x49, 0x97, 0xdc, 0x53,
        0xab, 0xa4, 0xf6, 0x8f,
        0x93, 0xe4, 0x65, 0xc1,
        0x56, 0x2c, 0x79, 0xc3,
        0xa5, 0x43, 0xea, 0x4e,
        0x2f, 0x41, 0x26, 0x39,
    };

    uint8_t product_bytes[32] = {};

    FieldElement a(LHS_BYTES);
    FieldElement b(RHS_BYTES);

    (a * b).to_bytes(product_bytes);

    REQUIRE(std::memcmp(product_bytes, EXPECTED_PRODUCT_BYTES, 32) == 0);
}

TEST_CASE("inverse", "[FieldElement]") {
    using namespace x25519_lite;

    constexpr uint8_t BYTES[32] = {
        0x23, 0x57, 0x48, 0x29,
        0x44, 0x32, 0x32, 0x95,
        0x34, 0x48, 0x38, 0x49,
        0x34, 0x57, 0x48, 0x19,
        0x31, 0x56, 0x34, 0x45,
        0x22, 0x43, 0x56, 0x54,
        0x34, 0x52, 0x22, 0x53,
        0x04, 0x63, 0x84, 0x23,
    };

    constexpr uint8_t EXPECTED_INVERSE_BYTES[32] = {
        0xec, 0x92, 0xa9, 0x66,
        0xc9, 0x66, 0xa5, 0xde,
        0x8f, 0xf4, 0xa6, 0x1b,
        0xc4, 0x66, 0x18, 0x73,
        0x4b, 0x79, 0xd4, 0xe6,
        0x9a, 0x86, 0x6f, 0xc6,
        0xe1, 0xd4, 0x87, 0xbe,
        0xd7, 0xf9, 0xd8, 0x2b,
    };

    FieldElement fe(BYTES);
    fe = fe.inverse();

    uint8_t inverse_bytes[32] = {};
    fe.to_bytes(inverse_bytes);

    REQUIRE(memcmp(inverse_bytes, EXPECTED_INVERSE_BYTES, 32) == 0);
}

TEST_CASE("square", "[FieldElement]") {
    using namespace x25519_lite;

    constexpr uint8_t BYTES[32] = {
        0x23, 0x57, 0x48, 0x29,
        0x44, 0x32, 0x32, 0x95,
        0x34, 0x48, 0x38, 0x49,
        0x34, 0x57, 0x48, 0x19,
        0x31, 0x56, 0x34, 0x45,
        0x22, 0x43, 0x56, 0x54,
        0x34, 0x52, 0x22, 0x53,
        0x04, 0x63, 0x84, 0x23,
    };
    constexpr uint8_t EXPECTED_BYTES[32] = {
        0x88,
        0x06,
        0x2b,
        0xde,
        0xde,
        0x4c,
        0xd4,
        0x3f,
        0xef,
        0x68,
        0x6a,
        0xcd,
        0xb2,
        0xd3,
        0x56,
        0x22,
        0xe2,
        0x83,
        0xdb,
        0x18,
        0x1a,
        0x7b,
        0x89,
        0xe2,
        0x09,
        0x03,
        0xed,
        0x1c,
        0x99,
        0x30,
        0xf1,
        0x0d,
    };
    FieldElement fe(BYTES);
    fe = fe.square();
    uint8_t res_bytes[32];
    fe.to_bytes(res_bytes);
    REQUIRE(memcmp(EXPECTED_BYTES, res_bytes, 32) == 0);
}

TEST_CASE("to_mod_p", "[FieldElement]") {
    using namespace x25519_lite;

    FieldElement fe(FE_P);
    REQUIRE(fe.is_mod_p() == false);
    REQUIRE(fe.to_mod_p() == FE_0);
}

TEST_CASE("pow2", "[FieldElement]") {
    using namespace x25519_lite;

    constexpr uint8_t BYTES[32] = {
        0x23, 0x57, 0x48, 0x29,
        0x44, 0x32, 0x32, 0x95,
        0x34, 0x48, 0x38, 0x49,
        0x34, 0x57, 0x48, 0x19,
        0x31, 0x56, 0x34, 0x45,
        0x22, 0x43, 0x56, 0x54,
        0x34, 0x52, 0x22, 0x53,
        0x04, 0x63, 0x84, 0x23,
    };

    constexpr uint8_t EXPECTED_BYTES[32] = {
        0x88,
        0x06,
        0x2b,
        0xde,
        0xde,
        0x4c,
        0xd4,
        0x3f,
        0xef,
        0x68,
        0x6a,
        0xcd,
        0xb2,
        0xd3,
        0x56,
        0x22,
        0xe2,
        0x83,
        0xdb,
        0x18,
        0x1a,
        0x7b,
        0x89,
        0xe2,
        0x09,
        0x03,
        0xed,
        0x1c,
        0x99,
        0x30,
        0xf1,
        0x0d,
    };

    FieldElement fe(BYTES);
    fe = fe.pow(FE_2);

    uint8_t bytes[32] = {};
    fe.to_bytes(bytes);

    REQUIRE(memcmp(bytes, EXPECTED_BYTES, 32) == 0);
}

TEST_CASE("diffie_hellman", "[x25519]") {
    using namespace x25519_lite;

    for (size_t i = 0; i < 100; ++i) {
        auto [a_sec_key, a_pub_key] = generate_keys();
        auto [b_sec_key, b_pub_key] = generate_keys();

        auto a_shared_secret = x25519(b_pub_key, a_sec_key);
        auto b_shared_secret = x25519(a_pub_key, b_sec_key);

        REQUIRE(a_shared_secret == b_shared_secret);
    }
}
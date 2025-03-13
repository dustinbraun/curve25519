#include <cassert>

#include <x25519_lite/x25519.hpp>

int main() {
    using namespace x25519_lite;

    auto [a_sec_key, a_pub_key] = generate_keys();
    auto [b_sec_key, b_pub_key] = generate_keys();

    auto a_shared_secret = diffie_hellman(b_pub_key, a_sec_key);
    auto b_shared_secret = diffie_hellman(a_pub_key, b_sec_key);

    assert(a_shared_secret == b_shared_secret);

    return 0;
}
#include <curve25519/x25519.hpp>

int main() {
    using namespace curve25519;

    auto [a_sec_key, a_pub_key] = generate_keys();
    auto [b_sec_key, b_pub_key] = generate_keys();

    auto a_shared_secret = x25519(b_pub_key, a_sec_key);
    auto b_shared_secret = x25519(a_pub_key, b_sec_key);

    assert(a_shared_secret == a_shared_secret);

    return 0;
}
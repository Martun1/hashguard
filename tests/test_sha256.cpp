// Official NIST / FIPS 180-4 test vectors for the from-scratch SHA-256.
#include "../src/sha256.hpp"
#include <iostream>

int main() {
    struct V { std::string in, out; } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
        {std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
    };
    int fails = 0;
    for (auto& t : v) {
        std::string got = hg::SHA256::of(t.in);
        if (got != t.out) { ++fails; std::cerr << "FAIL len=" << t.in.size() << " got " << got << "\n"; }
    }
    std::cout << (5 - fails) << "/5 SHA-256 test vectors passed\n";
    return fails ? 1 : 0;
}

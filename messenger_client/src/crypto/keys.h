#pragma once
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

struct KeyPair {
    Bytes publicKey;
    Bytes privateKey;
};

namespace CryptoUtils{
    KeyPair generateX25519KeyPair();
    KeyPair generateEd25519keyPair();
    Bytes secureRandomBytes(int length);
}
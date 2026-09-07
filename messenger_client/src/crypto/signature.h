#pragma once
#include <stdint.h>
#include <vector>


using Bytes = std::vector<uint8_t>;

namespace CryptoUtils_Signature {
    Bytes ed25519Sign (const Bytes &privateKey, const Bytes &message);
    bool ed25519Verify (const Bytes &publicKey, const Bytes &message, const Bytes &signature);
}
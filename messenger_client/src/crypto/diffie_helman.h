#pragma once
#include <cstdint>
#include <vector>
#include <crypto/keys.h>
#include "types.h"

// using Bytes = std::vector<uint8_t>;


namespace CryptoUtils{
    Bytes generateSharedSecret(const Bytes &privateKey, const Bytes &peerPublicKey);
}

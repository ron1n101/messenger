#pragma once
#include <vector>
#include <cstdint>
#include "types.h"

// using Bytes = std::vector<uint8_t>;

namespace CryptoUtils{
    Bytes hkdf(const Bytes &ikm, const Bytes &salt, const Bytes &info, size_t outputLength);
}
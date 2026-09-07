#include "catch_amalgamated.hpp"
#include <string>
#include "crypto/signature.h"
#include "crypto/crypto_exception.h"
#include "crypto/keys.h"

Bytes bytesFromHex(const std::string &hex)
{
    Bytes bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i++)
    {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// TODO: continue write to tests
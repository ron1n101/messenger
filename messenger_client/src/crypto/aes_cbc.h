#pragma once
#include "types.h"

namespace CryptoUtils{
    constexpr size_t kAesCbcIvLen = 16;

    Bytes aesCbcEncrypt(const Bytes &key, const Bytes &iv, const Bytes &plainText);
    Bytes aesCbcDecrypt(const Bytes &key, const Bytes &iv, const Bytes &cipherText);
}
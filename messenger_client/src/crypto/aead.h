#pragma once
#include "types.h"

namespace CryptoUtils {
    struct AeadCipherText {
        Bytes iv;
        Bytes cipherText;
        Bytes tag;
    };

    AeadCipherText aesGcmEncrypt (const Bytes &key, const Bytes &plainText, const Bytes &aad);
    Bytes aesGcmDecrypt(const Bytes &key, const AeadCipherText &ct, const Bytes &aad);
}
#pragma once
#include "aead.h"

namespace CryptoInternal{
    CryptoUtils::AeadCipherText aesGcmEncryptWithIv(
        const Bytes &key, const Bytes &iv, const Bytes &plainText, const Bytes &aad
    );
}
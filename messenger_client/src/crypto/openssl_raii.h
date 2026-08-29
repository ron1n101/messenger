#pragma once
#include <openssl/evp.h>
#include <memory>

namespace CryptoInternal {
    struct EvpPkeyDeleter {
        void operator()(EVP_PKEY *p) const {
            EVP_PKEY_free(p);
        }
    };

    struct EvpPKeyCtxDeleter{
        void operator()(EVP_PKEY_CTX *p) const {
            EVP_PKEY_CTX_free(p);
        }
    };

    using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPKeyCtxDeleter>;
}
#pragma once
#include <openssl/evp.h>
#include <openssl/kdf.h>
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


    struct EvpMdDeleter{
        void operator()(EVP_MD *p) const {
            EVP_MD_free(p);
        }
    };

    struct EvpMdCtxDeleter{
        void operator()(EVP_MD_CTX *p) const {
            EVP_MD_CTX_free(p);
        }
    };

    struct EvpKdfDeleter
    {
        void operator() (EVP_KDF *p) const{
            EVP_KDF_free(p);
        }
    };

    struct EvpKdfCtxDeleter
    {
        void operator() (EVP_KDF_CTX *p) const {
            EVP_KDF_CTX_free(p);
        }
    };


    using EvpPkeyPtr    = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPKeyCtxDeleter>;
    using EvpMdPtr      = std::unique_ptr<EVP_MD, EvpMdDeleter>;
    using EvpMdCtxPtr   = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
    using EvpKdfPtr        = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
    using EvpKdfCtxPtr  = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;


}
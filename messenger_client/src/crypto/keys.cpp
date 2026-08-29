#include "keys.h"
#include "openssl_raii.h"
#include "openssl_error.h"
#include <openssl/rand.h>

using namespace CryptoInternal;

static KeyPair generatePairByType(int keyType)
{
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(keyType, nullptr));
    throwIfFailed(EVP_PKEY_keygen_init(ctx.get()), "EVP_PKEY_keygen_init");

    EVP_PKEY *rawPkey = nullptr;
    throwIfFailed(EVP_PKEY_keygen(ctx.get(), &rawPkey), "EVP_PKEY_keygen");
    EvpPkeyPtr pkey(rawPkey);

    size_t pubLen = 32, privLen = 32;
    Bytes pub(pubLen), priv(privLen);

    throwIfFailed(EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pubLen), "get_raw_public_key");
    throwIfFailed(EVP_PKEY_get_raw_private_key(pkey.get(), priv.data(), &privLen), "get_raw_private_key");
    
    pub.resize(pubLen);
    priv.resize(privLen);
    return KeyPair{pub, priv};
}

KeyPair CryptoUtils::generateX25519KeyPair()
{
    return generatePairByType(EVP_PKEY_X25519);
}
KeyPair CryptoUtils::generateEd25519keyPair()
{
    return generatePairByType(EVP_PKEY_ED25519);
}

Bytes CryptoUtils::secureRandomBytes(int length)
{
    Bytes buf (length);
    throwIfFailed(RAND_bytes(buf.data(), length), "RAND_bytes");
    return buf;
}
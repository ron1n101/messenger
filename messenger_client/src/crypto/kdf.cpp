#include "kdf.h"
#include "openssl_raii.h"
#include "openssl_error.h"
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

using namespace CryptoInternal;

Bytes CryptoUtils_KDF::hkdf(const Bytes &ikm, const Bytes &salt, const Bytes &info, size_t outputLength)
{
    EvpKdfPtr kdf (EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    throwIfNull(kdf.get(), "EVP_KDF_fetch(HKDF)");

    
    
    EvpKdfCtxPtr ctx (EVP_KDF_CTX_new(kdf.get()));
    throwIfNull(ctx.get(), "EVP_KDF_CTX_new");

    const void *ikm_ptr = ikm.empty() ? nullptr : ikm.data();
    const void *salt_ptr = salt.empty() ? nullptr : salt.data();
    const void *info_ptr = info.empty() ? nullptr : info.data();

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char *>("SHA256"), 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<void*>(ikm_ptr), ikm.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<void*>(salt_ptr), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,  const_cast<void*>(info_ptr), info.size()),
        OSSL_PARAM_construct_end()
    };
    
    EVP_KDF_CTX_set_params(ctx.get(), params);

    Bytes output(outputLength);
    throwIfFailed(EVP_KDF_derive(ctx.get(), output.data(), output.size(), params), "EVP_KDF_derive(HKDF)");
    return output;
}
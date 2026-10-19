#include "hmac.h"
#include "crypto_exception.h"
#include "openssl_error.h"
#include "openssl_raii.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

using namespace CryptoInternal;

Bytes CryptoUtils::hmacSha256(const Bytes &key, const Bytes &data)
{
    // ШАГ 1: EvpMacPtr mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));  + throwIfNull

    EvpHmacPtr mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    throwIfNull(mac.get(), "EPV_HMAC_fetch");
    
    // ШАГ 2: EvpMacCtxPtr ctx(EVP_MAC_CTX_new(mac.get()));            + throwIfNull
    throwIfNull(EVP_MAC_CTX_new (mac.get()), "EVP_MAC_CTX_new");

    // ШАГ 3: параметр «какой хэш внутри»:
    //   OSSL_PARAM params[] = {
    //       OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
    //       OSSL_PARAM_construct_end()
    //   };
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_end()
    };


    // ШАГ 4: EVP_MAC_init(ctx, key_ptr, key.size(), params)
    //   ЛОВУШКА: пустой ключ. Я проверил: при key == nullptr с длиной 0 EVP_MAC_init
    //   возвращает 0 (ошибка), а при любом НЕ nullptr указателе — работает.
    //   RFC допускает пустой ключ. Как получишь «не-nullptr» для пустого вектора?
    //   (подсказка: ты уже решал похожее в hkdf с ikm_ptr/salt_ptr — но там было наоборот)
    EvpHmacCtxPtr ctx (EVP_MAC_CTX_new(mac.get()));
    throwIfNull(ctx.get(), "EVP_MAC_CTX_new failed");

    static const uint8_t kDummy = 0;
    const uint8_t *key_ptr = key.empty() ? &kDummy : key.data();
    throwIfFailed(EVP_MAC_init(ctx.get(), key_ptr, key.size(), params), "EVP_MAC_init");

    // ШАГ 5: EVP_MAC_update(ctx, data_ptr, data.size())
    //   Пустой data: можно ли вызвать update с nullptr, 0? Реши сам или проверь экспериментом.

    if (!data.empty())
    {
        throwIfFailed(EVP_MAC_update(ctx.get(), data.data(), data.size()), "EVP_MAC_Update");
    }
    // ШАГ 6: выход:
    //   Bytes out(kHmacSha256Len);
    //   size_t outLen = 0;
    //   EVP_MAC_final(ctx, out.data(), &outLen, out.size())
    //   Проверь, что outLen == 32 (иначе исключение).
    int kHmacSha256Len = 32;
    Bytes out(kHmacSha256Len);
    size_t outLen = 0;
     
    throwIfFailed(EVP_MAC_final(ctx.get(), out.data(), &outLen, out.size()), "EVP_MAC_final");
    if (outLen != kHmacSha256Len)
    {
        throw CryptoException ("EVP_MAC_final returned unexcpected length: "+std::to_string(outLen));
    }
    // ШАГ 7: return out;
    return out;
}

bool CryptoUtils::hmacSha256Verify(const Bytes &key, const Bytes &data, const Bytes &expectedMac)
{

    // 1) если expectedMac.size() != kHmacSha256Len — сразу false
    //    (длина тега не секрет, поэтому ранний выход допустим)
    if(expectedMac.size() != kHmacSha256Len)
    {
        return false;
    }
    // 2) Bytes actual = hmacSha256(key, data);
    Bytes actual = hmacSha256(key, data);
    // 3) return CRYPTO_memcmp(actual.data(), expectedMac.data(), kHmacSha256Len) == 0;
    //    ВОПРОС: почему нельзя просто actual == expectedMac (оператор == у vector)?
    //    Подсказка: «timing attack». Загугли это слово и сформулируй одним предложением.
    return CRYPTO_memcmp(actual.data(), expectedMac.data(), kHmacSha256Len) == 0;
}   
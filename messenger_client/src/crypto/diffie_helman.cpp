#include "diffie_helman.h"
#include "openssl/dh.h"
#include "openssl_raii.h"
#include "openssl_error.h"

using namespace CryptoInternal;

Bytes CryptoUtils_DH::generateSharedSecret(const Bytes &privateKey, const Bytes &peerPublicKey)
{
    
    // EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size()), nullptr));
    // throwIfFailed(EVP_PKEY_derive_init(ctx.get()), "EVP_PKEY_derive_init");
    // throwIfFailed

    // 1. Собрать EVP_PKEY* из privateKey — это МОЙ ключ
    //    (EVP_PKEY_new_raw_private_key, тип EVP_PKEY_X25519)
    EvpPkeyPtr privateKeyObj(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, privateKey.data(), privateKey.size()));
    throwIfNull(privateKeyObj.get(), "EVP_PKEY_new_raw_private_key");

    // 2. Собрать EVP_PKEY* из peerPublicKey — это ключ СОБЕСЕДНИКА
    //    (EVP_PKEY_new_raw_public_key, тот же тип)
    EvpPkeyPtr peerPublicKeyObj(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPublicKey.data(), peerPublicKey.size()));
    throwIfNull(peerPublicKeyObj.get(), "EVP_PKEY_new_raw_public_key");

    
    // 3. Создать контекст операции для МОЕГО ключа
    //    (EVP_PKEY_CTX_new, передаём указатель на мой EVP_PKEY)
    EvpPkeyCtxPtr ctx_key(EVP_PKEY_CTX_new(privateKeyObj.get(), nullptr));
    throwIfNull(ctx_key.get(), "EVP_PKEY_CTX_new");


    // 4. Инициализировать режим "derive" (то есть "я хочу вычислить общий секрет")
    //    (EVP_PKEY_derive_init)
    throwIfFailed(EVP_PKEY_derive_init(ctx_key.get()), "EVP_PKEY_derive_init");

    
    // 5. Сказать контексту, кто собеседник
    //    (EVP_PKEY_derive_set_peer, передаём указатель на EVP_PKEY собеседника)
    throwIfFailed(EVP_PKEY_derive_set_peer(ctx_key.get(), peerPublicKeyObj.get()), "EVP_PKEY_derive_set_peer");

    // 6. Узнать "сколько байт будет в результате?" — передать nullptr вместо буфера
    //    (EVP_PKEY_derive с нулевым буфером, но реальным указателем на переменную длины)
    size_t secretLen = 0;
    throwIfFailed(EVP_PKEY_derive(ctx_key.get(), nullptr, &secretLen ), "EVP_PKEY_derive (get length)");

    
    // 7. Выделить Bytes нужного размера и позвать derive второй раз, уже по-настоящему
    //    (EVP_PKEY_derive с реальным буфером)
    Bytes secret(secretLen);
    throwIfFailed(EVP_PKEY_derive(ctx_key.get(), secret.data(), &secretLen), "EVP_PKEY_derive");
    

    // 8. Вернуть результат
    return secret;
}
#include "signature.h"
#include "openssl_raii.h"
#include "openssl_error.h"
#include <openssl/evp.h>

using namespace CryptoInternal;

Bytes CryptoUtils_Signature::ed25519Sign(const Bytes &privateKey, const Bytes &message)
{
    // 1. Собрать EVP_PKEY* из privateKey (тип EVP_PKEY_ED25519)
    //    Не забудь throwIfNull — ты уже знаешь, почему это важно.
    
    EvpPkeyPtr privateKeyObj (EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, privateKey.data(), privateKey.size()));
    throwIfNull (privateKeyObj.get(), "EVP_PKEY_new_raw_private_key");

    // 2. Создать EVP_MD_CTX через EVP_MD_CTX_new().
    //    ВНИМАНИЕ: тебе нужно добавить в openssl_raii.h новый deleter и alias,
    //    по аналогии с EvpPkeyPtr/EvpPkeyCtxPtr, но для EVP_MD_CTX
    //    (функция очистки называется EVP_MD_CTX_free).

    EvpMdCtxPtr mdCtx (EVP_MD_CTX_new());
    throwIfNull (mdCtx.get(), "EVP_MD_CTX_new");

    // 3. EVP_DigestSignInit(mdCtx, nullptr, /* тип хэша: nullptr для Ed25519 */, nullptr, pkey)
    //    throwIfFailed(...)
    throwIfFailed(EVP_DigestSignInit(mdCtx.get(), nullptr, nullptr, nullptr, privateKeyObj.get()), "EVP_DigestSignInit");

    // 4. Узнать размер подписи: EVP_DigestSign(mdCtx, nullptr, &sigLen, message.data(), message.size())
    size_t signatureLen = 0;
    throwIfFailed(EVP_DigestSign(mdCtx.get(), nullptr, &signatureLen, message.data(), message.size()), "EVP_DigestSign (get signature length)");

    // 5. Выделить Bytes нужного размера и вызвать EVP_DigestSign ещё раз, уже по-настоящему
    Bytes signature (signatureLen);
    throwIfFailed(EVP_DigestSign(mdCtx.get(), signature.data(), &signatureLen, message.data(), message.size()), "EVP_DigestSign (sign message)");

    // 6. Вернуть подпись
    signature.resize(signatureLen);
    return signature;
}

bool CryptoUtils_Signature::ed25519Verify(const Bytes &publicKey, const Bytes &message, const Bytes &signature)
{
    // 1. Собрать EVP_PKEY* из publicKey (EVP_PKEY_new_raw_public_key)
    EvpPkeyPtr publicKeyObj (EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey.data(), publicKey.size()));
    throwIfNull (publicKeyObj.get(), "EVP_PKEY_new_raw_public_key");

    // 2. Создать EVP_MD_CTX
    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    throwIfNull (mdCtx.get(), "EVP_MD_CTX_new");

    // 3. EVP_DigestVerifyInit(...)
    throwIfFailed(EVP_DigestVerifyInit(mdCtx.get(), nullptr, nullptr, nullptr, publicKeyObj.get()), "EVP_DigestVerifyInit");

    // 4. EVP_DigestVerify(mdCtx, signature.data(), signature.size(), message.data(), message.size())
    //    ВАЖНЫЙ ВОПРОС ДЛЯ ТЕБЯ: эта функция возвращает int, а не просто "успех/провал" как большинство.
    //    Загляни в документацию — там ТРИ возможных исхода (не два!). throwIfFailed сюда НЕ подходит
    //    напрямую, потому что throwIfFailed кидает исключение при любом "не 1", а тебе нужно
    //    ОТДЕЛИТЬ "подпись неверна" (это не ошибка программы, это нормальный ожидаемый результат)
    //    от "что-то реально сломалось при проверке" (это уже настоящая ошибка).
    //    Подумай, как обработать эти три случая раздельно.

    int ret = EVP_DigestVerify(mdCtx.get(), signature.data(), signature.size(), message.data(), message.size());
    if (ret == 1)
    {
        return true;    // if sign correct
    }
    
    else if (ret == 0)
    {
        return false;   // sign not correct
    }
    
    else
    {
        throwIfFailed(ret, "EVP_DigestVerify");
    }    

}

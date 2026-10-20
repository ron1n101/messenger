#include "aes_cbc.h"
#include "crypto_exception.h"
#include "openssl_error.h"
#include "openssl_raii.h"
#include "secure_memory.h"
#include <openssl/evp.h>
#include <climits>

using namespace CryptoInternal;

namespace{
    constexpr size_t kKeyLen = 32;
    constexpr size_t kBlockLen = 16;

}


Bytes CryptoUtils::aesCbcEncrypt(const Bytes &key, const Bytes &iv, const Bytes &plainText)
{
    if (key.size() != kKeyLen)
    {
        throw CryptoException("AES-CBC: Key is invalid");
    }
    
    if (iv.size() != kAesCbcIvLen)
    {
        throw CryptoException("AES-CBC: Invalid IV length");
    }

    if (plainText.size() > INT_MAX)
    {
        throw CryptoException("AES-CBC: input too large");
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    throwIfNull(ctx.get(), "EVP_CIPHER_CTX_new ");

    // init
    throwIfFailed(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()), "EVP_EncryptInit_ex");

    // prepare place for future result
    Bytes cipherText(plainText.size() + kBlockLen);
    int written = 0;
    int finalWritten = 0;

    // encrypt data
    if (!plainText.empty())
    {
        throwIfFailed(EVP_EncryptUpdate(ctx.get(), cipherText.data(), &written, plainText.data(), static_cast<int>(plainText.size())), "EVP_EncryptUpdate ");
    }

    // final stage: add to additional bytes to future message
    throwIfFailed(EVP_EncryptFinal_ex(ctx.get(), cipherText.data() + written, &finalWritten), "EVP_EncryptFinal_ex");

    // trimming the excees bytes
    cipherText.resize(static_cast<size_t>(written) + static_cast<size_t>(finalWritten));
    
    // return our cipherText
    return cipherText;
}

Bytes CryptoUtils::aesCbcDecrypt(const Bytes &key, const Bytes &iv, const Bytes &cipherText)
{
    if (key.size() != kKeyLen)
    {
        throw CryptoException("AES-CBC: Key is invalid");
    }
    
    if (iv.size() != kAesCbcIvLen)
    {
        throw CryptoException("AES-CBC: Invalid IV length");
    }

    if (cipherText.empty() || cipherText.size() % kBlockLen != 0)
    {
        throw CryptoException("AES-CBC: Invalid cipherText length");
    }

    if (cipherText.size() > INT_MAX)
    {
        throw CryptoException("AES-CBC: input is too large");
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    throwIfNull(ctx.get(), "EVP_CIPHER_CTX_new" );

    // init
    throwIfFailed(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()), "EVP_DecryptInit_ex");

    // prepare for decryption
    Bytes plainText(cipherText.size() + kBlockLen);
    WipeOut guard(plainText);
    int written = 0;
    int finalWritten = 0;


    // decryption
    throwIfFailed(EVP_DecryptUpdate(ctx.get(), plainText.data(), &written, cipherText.data(), static_cast<int>(cipherText.size())), "EVP_DecryptUpdate");
    int ret = EVP_DecryptFinal_ex(ctx.get(), plainText.data() + written, &finalWritten);
    if (ret != 1)
    {
        throw CryptoException("AES-CBC: Decrypt failed (invalid padding)");
    }

    // trimming, disarm guard, return
    plainText.resize(static_cast<size_t>(written) + static_cast<size_t>(finalWritten));

    guard.disarm();
    return plainText;



}
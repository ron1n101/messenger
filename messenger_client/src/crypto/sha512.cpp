#include "sha512.h"
#include "crypto_exception.h"
#include "openssl_error.h"
#include <openssl/evp.h>
#include <string>

using namespace CryptoInternal;

CryptoUtils::Sha512::Sha512()
{
    
    // достаём метод sha-512 из пула
    m_md.reset(EVP_MD_fetch(nullptr, "SHA512", nullptr));
    throwIfNull(m_md.get(), "EVP_MD_fetch");


    // создаём контекст(блокнот условный)
    m_ctx.reset(EVP_MD_CTX_new());
    // подготавливаем блокнот к первому лупу
    throwIfNull(m_ctx.get(), "EVP_MD_CTX_new");
    restart();
}


void CryptoUtils::Sha512::restart()
{
    // рестарт = контекст, сам алгоритм, и движок
    throwIfFailed(EVP_DigestInit_ex(m_ctx.get(), m_md.get(), nullptr), "EVP_DigestInit_ex");
}

void CryptoUtils::Sha512::update(const uint8_t *data, size_t len)
{
    if (len == 0)
    {
        return;
    }
    if (data == nullptr)
    {
        throw CryptoException("SHA-512: data is null");
    }
    throwIfFailed(EVP_DigestUpdate(m_ctx.get(), data, len), "EVP_DigestUpdate");
}

Bytes CryptoUtils::Sha512::final()
{
    // готовим место под результат
    Bytes digest (kSha512Len);
    unsigned int digestLen = 0;
    
    // вычислаяем и получаем результат
    throwIfFailed(EVP_DigestFinal_ex(m_ctx.get(), digest.data(), &digestLen), "EVP_DigestFinal_ex");
    
    // проверяем длину
    if (digestLen != kSha512Len)
    {
        // throw CryptoException(std::to_string(digestLen));
        throw CryptoException("SHA-512: unexpected digest length: " + std::to_string(digestLen));
    }
    // перезапускаем для нового запроса
    restart();

    return digest;
}

Bytes CryptoUtils::sha512(const Bytes &data)
{
    CryptoUtils::Sha512 hasher;
    hasher.update(data.data(), data.size());
    return hasher.final();
}
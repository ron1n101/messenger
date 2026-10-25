#include "signal_bridge.h"
#include "aes_cbc.h"
#include "keys.h"
#include "hmac.h"
#include "secure_memory.h"
#include "crypto_exception.h"
#include "sha512.h"
#include <climits>
#include <cstring>
#include <new>

namespace 
{
    Bytes toBytes(const uint8_t *ptr, size_t len)
    {
        if (len == 0)
        {
            return Bytes{};
        }

        return Bytes(ptr, ptr+len);
    }


    bool isBadPointer(const void *ptr, size_t len)
    {
        return ptr == nullptr && len > 0;
    }
} // namespace 


// random digits func
int SignalBridge::randomFunc(uint8_t *data, size_t len, void *)
{
    if(len == 0)
    {
        return SG_SUCCESS;
    }
    
    if (data == nullptr || len > INT_MAX)
    {
        return SG_ERR_INVAL;
    }

    try
    {
        Bytes random = CryptoUtils::secureRandomBytes(static_cast<int>(len));
        WipeOut guard(random);
        std::memcpy(data, random.data(), len);
        return SG_SUCCESS;

    }
    catch(...)
    {
        return SG_ERR_UNKNOWN;
    }
}

int SignalBridge::encryptFunc(signal_buffer **output, int cipher,
    const uint8_t *key, size_t key_len, const uint8_t *iv,
    size_t iv_len, const uint8_t *plainText, size_t plainText_len, void *)
{
    if(output == nullptr)
    {
        return SG_ERR_INVAL;
    }

    *output = nullptr;

    // supporting CBC(ctr for older messages)
    if (cipher != SG_CIPHER_AES_CBC_PKCS5)
    {
        return SG_ERR_INVAL;
    }

    // if(isBadPointer(key, key_len) || (iv, iv_len) || (plainText, plainText_len))
    // {
    //     return SG_ERR_INVAL;
    // }

    if (isBadPointer(key, key_len ) ||
        isBadPointer(iv, iv_len) || isBadPointer(plainText, plainText_len))
    {
        return SG_ERR_INVAL;
    }

    try
    {
        // key_len == nullptr;
        Bytes keyBytes = toBytes(key, key_len);
        WipeOut keyGuard(keyBytes);
        
        Bytes plainBytes = toBytes(plainText, plainText_len);
        WipeOut plainGuard(plainBytes);

        // cipher message using by func aesEncrypt
        Bytes cipherBytes = CryptoUtils::aesCbcEncrypt(keyBytes, toBytes(iv, iv_len), plainBytes);

        //create buffer from signal lib
        signal_buffer *buffer = signal_buffer_create(cipherBytes.data(), cipherBytes.size());

        if (buffer == nullptr)
        {
            return SG_ERR_NOMEM;
        }

        // retranslate buffer to signal lib.
        *output = buffer;
        return SG_SUCCESS;
    }
    catch(const std::bad_alloc &) // if nehvatilo memory
    {
        return SG_ERR_NOMEM;
    }
    catch(...) // for ostalnih errors...
    {
        return SG_ERR_UNKNOWN;
    }
}


// decrypt func
int SignalBridge::decryptFunc(signal_buffer **output, int cipher,
    const uint8_t *key, size_t key_len, const uint8_t *iv,
    size_t iv_len, const uint8_t *cipherText, size_t cipherText_len, void *)
{
    if(output == nullptr)
    {
        return SG_ERR_INVAL;
    }

    *output = nullptr;

    // supporting CBC(ctr for older messages)
    if (cipher != SG_CIPHER_AES_CBC_PKCS5)
    {
        return SG_ERR_INVAL;
    }


    if (isBadPointer(key, key_len) ||
        isBadPointer(iv, iv_len) || isBadPointer(cipherText, cipherText_len))
    {
        return SG_ERR_INVAL;
    }

    try
    {
        Bytes keyBytes = toBytes(key, key_len);
        WipeOut keyGuard(keyBytes);

        // Bytes plainBytes = toBytes(plainText, plainText_len);
        Bytes cipherBytes = toBytes(cipherText, cipherText_len);
        WipeOut cipherGuard(cipherBytes);
        
        // decrypt stage
        Bytes plainBytes = CryptoUtils::aesCbcDecrypt(keyBytes, toBytes(iv, iv_len), cipherBytes);
        WipeOut plainGuard(plainBytes);

        // create buffer
        signal_buffer *buffer = plainBytes.empty() ? signal_buffer_alloc(0) : signal_buffer_create(plainBytes.data(), plainBytes.size());

        if(buffer == nullptr)
        {
            return SG_ERR_NOMEM;
        }
        *output = buffer;
        return SG_SUCCESS;
    }
    catch(const std::bad_alloc &) // if nehvatilo memory
    {
        return SG_ERR_NOMEM;
    }
    catch(...) // for ostalnih errors...
    {
        return SG_ERR_UNKNOWN;
    }
}


int SignalBridge::hmacInitFunc(void **hmac_context, const uint8_t *key, size_t key_len, void *)
{
    // if no space to put the context
    if (hmac_context == nullptr)
    {
        return SG_ERR_INVAL;
    }
    
    // library called anyway *cleanup*, if *init* has been failed. 
    // putting the nullptr,  instead of garbage
    *hmac_context = nullptr;

    // if key and key_len have the bad pointer, calling to badPointer
    if (isBadPointer(key, key_len))
    {
        return SG_ERR_INVAL;
    }

    try
    {
        // create copy of the key, and assign for key - guard(keyGuard)
        Bytes keyBytes = toBytes(key, key_len);
        WipeOut keyGuard(keyBytes);

        *hmac_context = new CryptoUtils::HmacSha256(keyBytes);
        return SG_SUCCESS;
    }
    catch(const std::bad_alloc &)
    {
        return SG_ERR_NOMEM;
    }
    catch (...)
    {
        return SG_ERR_UNKNOWN;
    }
}

int SignalBridge::hmacUpdateFunc(void *hmac_context, const uint8_t *data, size_t data_len, void *)
{
    if (hmac_context == nullptr)
    {
        return SG_ERR_INVAL;
    }
    try
    {
        // мы знаем что мы ищем, поэтому кастуем hmac  class HmacSha256 в hmac_context
        auto *hmac = static_cast<CryptoUtils::HmacSha256 *> (hmac_context);
        // update
        hmac->update(data, data_len); 
        return SG_SUCCESS;
    }
    catch(...)
    {
        return SG_ERR_UNKNOWN;
    }
}

int SignalBridge::hmacFinalFunc(void *hmac_context, signal_buffer **output, void *user_data)
{
    if(hmac_context == nullptr || output == nullptr)
    {
        return SG_ERR_INVAL;
    }

    *output = nullptr;

    try
    {
        auto *hmac = static_cast<CryptoUtils::HmacSha256 *>(hmac_context);
        Bytes mac = hmac->final();

        WipeOut macGuard(mac);

        signal_buffer *buffer = signal_buffer_create(mac.data(), mac.size());
        if (buffer == nullptr)
        {
            return SG_ERR_NOMEM;
        }

        *output = buffer;
        return SG_SUCCESS;
    }
    catch(const std::bad_alloc &)
    {
        return SG_ERR_NOMEM;
    }
    catch(...)
    {
        return SG_ERR_UNKNOWN;
    }
}

void SignalBridge::hmacCleanupFunc(void *hmac_context, void *)
{
    delete static_cast<CryptoUtils::HmacSha256 *> (hmac_context);
}



int SignalBridge::sha512InitFunc(void **digest_context, void *)
{
    if(digest_context == nullptr)
    {
        return SG_ERR_INVAL;
    }

    *digest_context = nullptr;

    try
    {
        *digest_context = new CryptoUtils::Sha512();
        return SG_SUCCESS;
    }

    catch(const std::bad_alloc &)
    {
        return SG_ERR_NOMEM;
    }
    catch (...)
    {
        return SG_ERR_UNKNOWN;
    }
}

int SignalBridge::sha512UpdateFunc(void *digest_context, const uint8_t *data, size_t data_len, void *)
{
    // проверяем, пустой ли дайджет?
    if (digest_context == nullptr)
    {
        return SG_ERR_INVAL;
    }
    // если да, то объявлем хэшер и кастуем дайджест контекст под sha512
    try
    {
        auto *hasher = static_cast<CryptoUtils::Sha512 *> (digest_context);
        // update
        hasher->update(data, data_len); 
        return SG_SUCCESS;
    }
    catch(...)
    {
        return SG_ERR_UNKNOWN;
    }
}

int SignalBridge::sha512FinalFunc(void *digest_context, signal_buffer **output, void *)
{
    if(digest_context == nullptr || output == nullptr)
    {
        return SG_ERR_INVAL;
    }

    *output = nullptr;

    try
    {
        auto *hasher = static_cast<CryptoUtils::Sha512 *>(digest_context);
        Bytes digest = hasher->final();

        signal_buffer *buffer = signal_buffer_create(digest.data(), digest.size());
        if (buffer == nullptr)
        {
            return SG_ERR_NOMEM;
        }

        *output = buffer;
        return SG_SUCCESS;
    }
    catch(const std::bad_alloc &)
    {
        return SG_ERR_NOMEM;
    }
    catch(...)
    {
        return SG_ERR_UNKNOWN;
    }
}

void SignalBridge::sha512CleanupFunc(void *digest_context, void *)
{
    delete static_cast<CryptoUtils::Sha512 *> (digest_context);
}
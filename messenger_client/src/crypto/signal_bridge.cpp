#include "signal_bridge.h"
#include "aes_cbc.h"
#include "keys.h"
#include "secure_memory.h"
#include "crypto_exception.h"
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
    size_t iv_len, const uint8_t *plainText, size_t plainText_len,
    void *)
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
    size_t iv_len, const uint8_t *cipherText, size_t cipherText_len,
    void *)
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

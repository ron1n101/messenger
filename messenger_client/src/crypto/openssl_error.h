#pragma once
#include <openssl/err.h>
#include "crypto_exception.h"

namespace CryptoInternal {

    inline void throwIfFailed (int ret, const char *operation) {
        if ( ret != 1)
        {
            unsigned long errCode = ERR_get_error();
            char buf[256];
            ERR_error_string_n(errCode, buf, sizeof(buf));
            throw CryptoException(std::string (operation)+ " failed: " + buf); 

        }
    }
    inline void throwIfNull(const void *ptr, const char *operation)
    {
        if (ptr == nullptr)
        {
            unsigned long errCode = ERR_get_error();
            char buf[256];
            ERR_error_string_n(errCode, buf, sizeof(buf));
            throw CryptoException(std::string (operation)+ " failed: " + buf); 
        }
    }
}
#pragma once
#include "types.h"
#include <openssl/evp.h>

struct WipeOut{
    Bytes &buf;
    bool armed = true;

    explicit WipeOut(Bytes &b) : buf(b){}
    WipeOut(const WipeOut&) = delete;
    WipeOut& operator=(const WipeOut&) = delete;
    ~WipeOut()
    {
        if (armed && !buf.empty())
        {
            OPENSSL_cleanse(buf.data(), buf.size());
        }
    }
    void disarm()
    {
        armed = false;
    }
    
};
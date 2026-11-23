#pragma once
#include <string>
#include "crypto/crypto_exception.h"

class SignalException : public CryptoException
{

public:
    SignalException(const std::string &message, int code)
        : CryptoException(message + " (code " + std::to_string(code) + ")"),
          m_code(code)
    {
    }

    int coode () const
    {
        return m_code;
    }
private:
    int m_code;
};
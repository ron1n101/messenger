#pragma once
#include <stdexcept>
#include <string>

class CryptoException : public std::runtime_error {
    public:
    explicit CryptoException(const std::string &msg) : std::runtime_error(msg) {}

};
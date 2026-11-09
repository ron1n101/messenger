#pragma once
#include <string>
#include "types.h"

namespace CryptoUtils
{
    // Байты -> строка base64 (RFC 4648, без переносов строк).
    std::string base64Encode (const Bytes &input);


    // Строка base64 -> байты. Строгая проверка: длина кратна 4, только символы алфавита,
    // '=' только в конце (не больше двух). Иначе CryptoException.
    void base64Decode (const std::string &input, Bytes &output);


}
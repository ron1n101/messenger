#pragma once
#include "types.h"

namespace CryptoUtils {
    // Длина HMAC-SHA256 в байтах.
    constexpr size_t kHmacSha256Len = 32;

    // Вычисляет HMAC-SHA256 для данных data с ключом key.
    // Возвращает MAC длиной 32 байта.
    Bytes hmacSha256(const Bytes &key, const Bytes &data);

    // Проверяет, что HMAC-SHA256 для данных data с ключом key совпадает с expcetedMac.
    // Возвращает true, если совпадает, false — если нет.
    bool hmacSha256Verify(const Bytes &key, const Bytes &data, const Bytes &expectedMac);
}
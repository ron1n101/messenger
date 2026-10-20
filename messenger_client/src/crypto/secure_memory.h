#pragma once
#include "types.h"
#include <openssl/evp.h>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace CryptoUtils {
    
    void secureZero(void *ptr, size_t len);
    void secureZero(Bytes &data);
}
class SecureBuffer
{
public:
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();

    SecureBuffer (const SecureBuffer &) = delete;   // Запрет на создание нового объекта копией
    SecureBuffer &operator=(const SecureBuffer &) = delete; // Запрет на копирование уже в созданый объект
    SecureBuffer(SecureBuffer &&other) noexcept;        // создать новый объект забрав ресурсы с предыдущего
    SecureBuffer &operator=(SecureBuffer &&other) noexcept; // передать ресурсы уже созданному объекту

    uint8_t *data();
    const uint8_t *data() const;
    size_t size() const;
    bool empty() const;

private:
    std::unique_ptr <uint8_t[]> m_data;
    size_t m_size = 0;

};

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


#include "secure_memory.h"
#include <openssl/crypto.h>
#include <utility>

// Secure Zero - затирка. Чистит за собой следы.
void CryptoUtils::secureZero(void *ptr, size_t len)
{
    if (ptr == nullptr || len == 0)
    {
        return;
    }
    OPENSSL_cleanse(ptr, len);
}

void CryptoUtils::secureZero(Bytes &data)
{
    secureZero(data.data(), data.size());
}


// Secure Buffer
SecureBuffer::SecureBuffer(size_t size)
: m_data(std::make_unique<uint8_t[]>(size)), m_size(size) {}


SecureBuffer::~SecureBuffer()
{
    // TODO ШАГ 4: затереть m_size байт, начиная с m_data.get().
    CryptoUtils::secureZero(m_data.get(), m_size);
    // Освобождать память руками не надо — это сделает unique_ptr после деструктора.
}

SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
    : m_data(/* TODO ШАГ 5: забрать указатель у other (подсказка: std::move) */ std::move(other.m_data)),
      m_size(/* TODO: забрать размер у other */ other.m_size)
{
    // TODO: у other обнулить размер (указатель у него уже пустой после std::move).
    other.m_size = 0;
}

SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept
{
    // TODO ШАГ 6а: если this == &other — вернуть *this сразу.
    if(this == &other) return *this;

    // TODO ШАГ 6б: ЗАТЕРЕТЬ то, что лежит в this сейчас (старый секрет).
    CryptoUtils::secureZero(m_data.get(), m_size);
    m_data = std::move(other.m_data);
    m_size = other.m_size;

    // TODO ШАГ 6в: забрать указатель и размер у other, у other обнулить размер.
    other.m_size = 0;
    return *this;
}

uint8_t *SecureBuffer::data()             { return m_data.get(); }
const uint8_t *SecureBuffer::data() const { return m_data.get(); }
size_t SecureBuffer::size() const         { return m_size; }
bool SecureBuffer::empty() const          { return m_size == 0; }
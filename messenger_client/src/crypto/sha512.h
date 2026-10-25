#pragma once
#include "types.h"
#include "openssl_raii.h"

namespace CryptoUtils
{
    constexpr size_t kSha512Len = 64;

    Bytes sha512(const Bytes &data);

    class Sha512
    {
        public:
            Sha512();
            // update - возможность добавить что то ещё к функции (кусок какой то)
            void update(const uint8_t *data, size_t len);
            // получаем 64 байта и готовимся к следующему вызову
            Bytes final();
        
        private:
            void restart(); // чтобы начать хэш с нуля

            CryptoInternal::EvpMdPtr m_md;  // нужен для каждого рестарта
            CryptoInternal::EvpMdCtxPtr m_ctx; 
    };
}
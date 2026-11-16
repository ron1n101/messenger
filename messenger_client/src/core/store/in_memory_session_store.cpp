#include "core/store/in_memory_identity_store.h"
#include "crypto/crypto_exception.h"
#include "crypto/secure_memory.h"
#include "curve.h"
#include <memory>
#include <new>


namespace {
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;
    using SecretBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_bzero_free)>;

    // создаём копию через сигналовский буффер в байты
    Bytes copyBuffer(const signal_buffer *buffer)
    {
        return Bytes(signal_buffer_const_data(buffer), signal_buffer_const_data(buffer) + signal_buffer_len(buffer));
    }
}

InMemoryIdentityStore::InMemoryIdentityStore(const ratchet_identity_key_pair *ownIdentity, uint32_t ownRegistrationId)
{
    // проверка на наличие своего identity ключа
    if (ownIdentity == nullptr)
    {
        throw CryptoException ("InMemoryIdentityStore: identity is null");
    }

    // публичную часть передам в байты
    signal_buffer *rawPublicKey = nullptr;
    if (ec_public_key_serialize(&rawPublicKey, ratchet_identity_key_pair_get_public(ownIdentity)) < 0)
    {
        throw CryptoException("InMemoryIdentityStore: public key serialize failed");
    }
    SignalBufferPtr publicBuffer(rawPublicKey, signal_buffer_free);

    // приватную тоже в байты
    signal_buffer *rawPrivateKey = nullptr;
    if (ec_private_key_serialize(&rawPrivateKey, ratchet_identity_key_pair_get_private(ownIdentity)) < 0)
    {
        throw CryptoException("InMemoryIdentityStore: private key serialize failed");
    }
    SecretBufferPtr privateBuffer(rawPrivateKey, signal_buffer_bzero_free);

    // копируем всё в поля для публичный и приватных байтов
    m_ownPublicKey = copyBuffer(publicBuffer.get());
    m_ownPrivateKey = copyBuffer(privateBuffer.get());
}


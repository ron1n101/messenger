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

InMemoryIdentityStore::~InMemoryIdentityStore()
{
    CryptoUtils::secureZero(m_ownPrivateKey);
}


signal_protocol_identity_key_store InMemoryIdentityStore::toSignalStore()
{
    signal_protocol_identity_key_store store {};

    store.get_identity_key_pair = &getIdentityKeyPair;
    store.get_local_registration_id = &getLocalRegistrationId;
    store.save_identity = &saveIdentity;
    store.is_trusted_identity = &isTrustedIdentity;
    store.destroy_func = nullptr;

    store.user_data = this;
    return store;
}

int InMemoryIdentityStore::getIdentityKeyPair(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
{
    // находим наш объект
    auto *self = static_cast<InMemoryIdentityStore*> (user_data);

    // находим наш публичный буфер
    signal_buffer *publicBuffer = signal_buffer_create(self->m_ownPublicKey.data(), self->m_ownPublicKey.size());
    if (publicBuffer == nullptr)
    {
        return SG_ERR_NOMEM;
    }
    
    // находим наш приватный буффер
    signal_buffer *privateBuffer = signal_buffer_create(self->m_ownPrivateKey.data(), self->m_ownPrivateKey.size());
    if (privateBuffer == nullptr)
    {
        signal_buffer_free(publicBuffer);
        return SG_ERR_NOMEM;
    }


    // отдаём наши буферы сигналу
    *public_data = publicBuffer;
    *private_data = privateBuffer;
    return 0;
}

int InMemoryIdentityStore::getLocalRegistrationId(void *user_data, uint32_t *registration_id)
{
    // записываем наш ИД по указателю
    *registration_id = static_cast<InMemoryIdentityStore *>(user_data)->m_ownRegistrationId;
}

int InMemoryIdentityStore::saveIdentity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    // находим наш объект
    auto *self = static_cast<InMemoryIdentityStore *> (user_data);

    try
    {
        // забываем нашего собеседника (удаляем его ключ публичный у себя в сессии)
        if (key_data == nullptr)
        {
            self->m_trustedKeys.erase(toAddressKey(address));
        }

        // запоминаем нашего собеседника (заменяем или запоминаем ключ у себя)
        else{
            self->m_trustedKeys[toAddressKey(address)] = Bytes(key_data, key_data + key_len);
            return 0;
        }
    }
    catch(const std::bad_alloc& e)
    {
        return SG_ERR_NOMEM;
    }
}

int InMemoryIdentityStore::isTrustedIdentity(const signal_protocol_address *address, uint8_t key_data, size_t key_len, void *user_data)
{
    auto *self = static_cast<InMemoryIdentityStore *> (user_data);

    // есть ли ключ который был сохранён для этого адресса?
    auto it = self->m_trustedKeys.find(toAddressKey(address));

    // если не встречали и это наша первая встреча, то превентивно доверяем
    if (it == self->m_trustedKeys.end())
    {
        return 1;
    }
    // если встречали - то доверяем, только если ключ тот же самый что и был при знакомстве
    return (it->second == Bytes(key_data, key_data + key_len)) ? 1 : 0;
}
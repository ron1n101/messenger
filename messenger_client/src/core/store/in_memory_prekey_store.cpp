#include "core/store/in_memory_prekey_store.h"
#include "crypto/secure_memory.h"
#include <new>


// деструктор
InMemoryPreKeyStore::~InMemoryPreKeyStore()
{
    wipeAll(m_preKeys);
    wipeAll(m_signedPreKey);
}

// проходимся по всему словарю и затераем каждое значение

void InMemoryPreKeyStore::wipeAll(std::map<uint32_t, Bytes> &keys)
{
    for (auto &entry : keys)
    {
        CryptoUtils::secureZero(entry.second);
    }
}


// назначение для prekeys
signal_protocol_pre_key_store InMemoryPreKeyStore::toPreKeyStore()
{
    signal_protocol_pre_key_store store {};
    store.load_pre_key = &loadPreKey;
    store.store_pre_key = &storePreKey;
    store.contains_pre_key = &containsPreKey;
    store.remove_pre_key = &removePreKey;
    store.destroy_func = nullptr;
    store.user_data = this;
    return store;
}

// назначение для signed_prekeys
signal_protocol_signed_pre_key_store InMemoryPreKeyStore::toSignedPreKeyStore()
{
    signal_protocol_signed_pre_key_store store {};
    store.load_signed_pre_key = &loadSignedPreKey;
    store.store_signed_pre_key = &storeSignedPreKey;
    store.contains_signed_pre_key = &containsSignedPreKey;
    store.remove_signed_pre_key = &removeSignedPreKey;
    store.destroy_func = nullptr;
    store.user_data = this;
    return store;
}

// помощники
int InMemoryPreKeyStore::loadFrom(std::map<uint32_t, Bytes> &keys, signal_buffer **record, uint32_t id)
{
    // находим запись по номеру
    auto it = keys.find(id);

    // если не нашли - выдаём исключение из библиотеки сигнала
    if( it == keys.end())
    {
        return SG_ERR_INVALID_KEY_ID;
    }

    // если нашли, то создаём новый буффер и кидаём туда то что нашли
    signal_buffer *buffer = signal_buffer_create(it->second.data(), it->second.size());
    if (buffer == nullptr)
    {
        return SG_ERR_NOMEM;
    }

    // и отдаём буффер и возращаем сигналовский сигнал success
    *record = buffer;
    return SG_SUCCESS;
}

int InMemoryPreKeyStore::storeInfo(std::map <uint32_t, Bytes> &keys, uint32_t id, const uint8_t *record, size_t record_len)
{
    try
    {
    // если под каким то номер создаётся дубликат, мы его перезаписываем (затираем старое перед записыванием)
        auto it  = keys.find(id);
        if (it != keys.end())
        {
            CryptoUtils::secureZero(it->second);
        }
    // и кладём эту копию в стор
        keys[id] = Bytes(record, record + record_len);
        return SG_SUCCESS;
    }
    catch(const std::bad_alloc &)
    {
        return SG_ERR_NOMEM;
    }
    
}

int InMemoryPreKeyStore::removeFrom(std::map <uint32_t, Bytes> &keys, uint32_t id)
{
    auto it = keys.find(id);
    if (it != keys.end())
    {
        CryptoUtils::secureZero(it->second);
        keys.erase(it);
    }
    return SG_SUCCESS;
}




// коллбэки чтобы достать из user_data и вызвать помощника с нужным словарём
int InMemoryPreKeyStore::loadPreKey (signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    return loadFrom(static_cast<InMemoryPreKeyStore *> (user_data)->m_preKeys, record, pre_key_id);
}

int InMemoryPreKeyStore::storePreKey (uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    return storeInfo(static_cast<InMemoryPreKeyStore *> (user_data)->m_preKeys, pre_key_id, record, record_len);
}

int InMemoryPreKeyStore::containsPreKey (uint32_t pre_key_id, void *user_data)
{
    return static_cast<InMemoryPreKeyStore *> (user_data)->m_preKeys.count(pre_key_id) > 0 ? 1 : 0;
}

int InMemoryPreKeyStore::removePreKey (uint32_t pre_key_id, void *user_data)
{
    return removeFrom(static_cast<InMemoryPreKeyStore *> (user_data)->m_preKeys, pre_key_id);
}




int InMemoryPreKeyStore::loadSignedPreKey (signal_buffer **record, uint32_t signed_pre_key_id, void *user_data)
{
    return loadFrom(static_cast<InMemoryPreKeyStore *> (user_data)->m_signedPreKey, record, signed_pre_key_id);
}

int InMemoryPreKeyStore::storeSignedPreKey (uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    return storeInfo(static_cast<InMemoryPreKeyStore *> (user_data)->m_signedPreKey, signed_pre_key_id, record, record_len);
}
int InMemoryPreKeyStore::containsSignedPreKey (uint32_t signed_pre_key_id, void *user_data)
{
    return static_cast<InMemoryPreKeyStore *> (user_data)->m_signedPreKey.count(signed_pre_key_id) > 0 ? 1 : 0;
}

int InMemoryPreKeyStore::removeSignedPreKey (uint32_t signed_pre_key_id, void *user_data)
{
    return removeFrom(static_cast<InMemoryPreKeyStore *> (user_data)->m_signedPreKey, signed_pre_key_id);
}

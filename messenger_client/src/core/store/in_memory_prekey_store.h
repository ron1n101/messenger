#pragma once
#include <cstdint>
#include <map>
#include "crypto/types.h"
#include "signal_protocol.h"

class InMemoryPreKeyStore
{
public:
    InMemoryPreKeyStore() = default;
    ~InMemoryPreKeyStore();

    // запрет на копирование
    InMemoryPreKeyStore (const InMemoryPreKeyStore &) = delete;

    // запрет оператора присваивания копированием (= delete)
    InMemoryPreKeyStore &operator = (const InMemoryPreKeyStore &) = delete;

    // структуры для libsignal
    signal_protocol_pre_key_store toPreKeyStore();
    signal_protocol_signed_pre_key_store toSignedPreKeyStore();

    // для тестов
    size_t preKeyCount() const { return m_preKeys.size(); }
    size_t signedPreKeyCount() const { return m_signedPreKey.size(); }

private:
    // необходимые коллбеки
    // для прекей
    static int loadPreKey (signal_buffer **record, uint32_t pre_key_id, void *user_data);
    static int storePreKey (uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
    static int containsPreKey (uint32_t pre_key_id, void *user_data);
    static int removePreKey (uint32_t pre_key_id, void *user_data);

    // для подписанных прекеях
    static int loadSignedPreKey (signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);
    static int storeSignedPreKey (uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);
    static int containsSignedPreKey (uint32_t signed_pre_key_id, void *user_data);
    static int removeSignedPreKey (uint32_t signed_pre_key_id, void *user_data);

    // общие хелперы (загрузить откуда, стор инфо, убрать откуда, всё отчистить.)
    static int loadFrom(std::map<uint32_t, Bytes> &keys, signal_buffer **record, uint32_t id);
    static int storeInfo(std::map <uint32_t, Bytes> &keys, uint32_t id, const uint8_t *record, size_t record_len);
    static int removeFrom(std::map <uint32_t, Bytes> &keys, uint32_t id);
    static void wipeAll (std::map<uint32_t, Bytes> &keys);

    std::map<uint32_t, Bytes> m_preKeys;
    std::map<uint32_t, Bytes> m_signedPreKey;

};
#pragma once
#include <map>
#include "crypto/types.h"
#include "core/store/store_utils.h"

// класс хранилища
class InMemorySessionStore
{
public:
    InMemorySessionStore() = default;
    
    // запрет на копирование
    InMemorySessionStore (const InMemorySessionStore &) = delete;

    // запрет оператора присваивания копированием (= delete)
    InMemorySessionStore &operator = (const InMemorySessionStore &) = delete;

    // собираем сигнал структуру
    signal_protocol_session_store toSignalStore();

    // сколько сессий хранится (это для тестов)
    size_t size() const
    {
        return m_sessions.size();
    }

private:
    // коллбеки
    static int loadSession(signal_buffer **record, signal_buffer **user_record, const signal_protocol_address *address, void *user_data);
    
    static int getSubDeviceSessions(signal_int_list **sessions, const char *name, size_t name_len, void *user_data);

    static int storeSession (const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data);

    static int containsSession (const signal_protocol_address *address, void *user_data);

    static int deleteSession (const signal_protocol_address *address, void *user_data);

    static int deleteAllSession (const char *name, size_t name_len, void *user_data);

    // словарь
    std::map<AddressKey, Bytes> m_sessions;
};

#include "core/store/in_memory_session_store.h"
#include <new>

signal_protocol_session_store InMemorySessionStore::toSignalStore()
{
    // пустая структура
    signal_protocol_session_store store{};

    // поля указатели
    store.load_session_func = &loadSession;
    store.get_sub_device_sessions_func = &getSubDeviceSessions;
    store.store_session_func = &storeSession;
    store.contains_session_func = &containsSession;
    store.delete_session_func = &deleteSession;
    store.delete_all_sessions_func = &deleteAllSession;

    store.destroy_func = nullptr;
    
    // для того чтобы нашла и вернула нужный коллбек из стора
    store.user_data = this;
    return store;

}


int InMemorySessionStore::loadSession(signal_buffer **record, signal_buffer **, const signal_protocol_address *address, void *user_data)
{
    // находим объект
    auto *self = static_cast<InMemorySessionStore *> (user_data);

    //ищем адрес по записи
    auto it = self->m_sessions.find(toAddressKey(address));

    // если не нашли то возращаем 0
    if (it == self->m_sessions.end())
    {
        return 0;
    }

    // если нашли, надо создать новый буффер с копией байтов
    signal_buffer *buffer = signal_buffer_create(it->second.data(), it->second.size());

    if(buffer == nullptr)
    {
        return SG_ERR_NOMEM;
    }

    // отдаём буффер и говворим что "нашли"
    *record = buffer;
    return 1;
}

int InMemorySessionStore::getSubDeviceSessions(signal_int_list **sessions, const char *name, size_t name_len, void *user_data)
{
    // надо найти наш объект
    auto *self = static_cast<InMemorySessionStore *> (user_data);

    //создаём пустой список чисел библиотеки
    signal_int_list *list = signal_int_list_alloc();
    if (list == nullptr)
    {
        return SG_ERR_NOMEM;
    }
    // имя которое надо найти - строка
    const std::string wanted(name, name_len);

    // пройтись по всем сессиям - собрать номера устройств
    for (const auto &entry : self->m_sessions)
    {
        if (entry.first.first == wanted || entry.first.second != 1)
        {
            signal_int_list_push_back(list, entry.first.second);
        }
    }

    // отдаём список и возвращаем количество 
    *sessions = list;
    return static_cast<int>(signal_int_list_size(list));
}

int InMemorySessionStore::storeSession(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *, size_t , void *user_data)
{
    // находим объект
    auto *self = static_cast<InMemorySessionStore *> (user_data);

    try
    {   // кладём копию байтов в map
        self->m_sessions[toAddressKey(address)] = Bytes(record, record + record_len);
        return 0;
    }

    catch(std::bad_alloc &)
    {
        return SG_ERR_NOMEM;
    }
}

int InMemorySessionStore::containsSession(const signal_protocol_address *address, void *user_data)
{
    auto *self = static_cast<InMemorySessionStore*> (user_data);
    
    // возвращаем 1, если запись есть, иначе возвращаем 0
    return self->m_sessions.count(toAddressKey(address)) > 0 ? 1 : 0;
}

int InMemorySessionStore::deleteSession(const signal_protocol_address *address, void *user_data)
{
    auto *self = static_cast<InMemorySessionStore*> (user_data);
    self->m_sessions.erase(toAddressKey(address));
}

int InMemorySessionStore::deleteAllSession(const char *name, size_t name_len, void *user_data)
{
    auto *self = static_cast<InMemorySessionStore*> (user_data);

    const std::string wanted(name, name_len);
    int deleted = 0;

    for (auto it = self->m_sessions.begin(); it != self->m_sessions.end(); )
    {
        if (it->first.first == wanted)
        {
            it = self->m_sessions.erase(it);
            ++deleted;
        }
        else{
            ++it;
        }
    }
    return deleted;
}



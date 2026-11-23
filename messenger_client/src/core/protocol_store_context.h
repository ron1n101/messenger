#pragma once
#include <string>
#include "signal_protocol.h"
#include "core/store/in_memory_session_store.h"
#include "core/store/in_memory_identity_store.h"

class ProtocolStoreContext
{

public:
    ProtocolStoreContext(signal_context *context, InMemorySessionStore &sessions, InMemoryIdentityStore &identities);
    ~ProtocolStoreContext();

    ProtocolStoreContext (const ProtocolStoreContext &) = delete;

    // запрет оператора присваивания копированием (= delete)
    ProtocolStoreContext &operator = (const ProtocolStoreContext &) = delete;

    // сырой указатель для функции либсигнал
    signal_protocol_store_context * get() const { return m_storeContext; }

    // есть ли сессия с собеседником
    bool hasSession (const std::string &contactName, int deviceId) const;

private:
    signal_protocol_store_context *m_storeContext = nullptr;
};
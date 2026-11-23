#pragma once
#include <string>
#include "signal_protocol.h"
#include "session_pre_key.h"
#include "core/protocol_store_context.h"

class SessionEstablisher
{
public:
    SessionEstablisher(signal_context *context, ProtocolStoreContext &stores);

    void establishSession(const std::string &contactName, int deviceId, session_pre_key_bundle *bundle);

private:
    signal_context *m_context;
    ProtocolStoreContext &m_stores;
};
#pragma once
#include <string>
#include "crypto/types.h"
#include "signal_protocol.h"
#include "core/protocol_store_context.h"


struct EncryptedMessage
{
    int type = 0;
    Bytes body;
};

// шифрование и расшифровка
class MessageCipher
{
public:
    static constexpr int kPreKeyMessage = 3;
    static constexpr int kSignalMessage = 2;

    MessageCipher(signal_context *context, ProtocolStoreContext &stores);
    EncryptedMessage encrypt(const std::string &contactName, int deviceId, const Bytes &plainText);
    Bytes decrypt (const std::string &contactName, int deviceId, const EncryptedMessage &message);

private:
    signal_context *m_context;
    ProtocolStoreContext &m_stores;
};

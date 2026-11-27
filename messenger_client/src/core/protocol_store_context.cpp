#include "core/protocol_store_context.h"
#include "core/signal_exception.h"
#include <memory>

ProtocolStoreContext::ProtocolStoreContext(signal_context *context, InMemorySessionStore &sessions, InMemoryIdentityStore &identities, InMemoryPreKeyStore *preKeys)
{
    // проверка, без общего контекста - мы ничего не создаём
    if (context == nullptr)
    {
        throw CryptoException ("ProtocolStoreContext: context is null");
    }


    // создаём пустой контекст хранилищ

    signal_protocol_store_context *raw = nullptr;
    int result = signal_protocol_store_context_create (&raw, context);
    if (result < 0)
    {
        throw SignalException ("signal_protocol_store_context_create failed", result);
    }

    // создаём временную обёртку
    std::unique_ptr <signal_protocol_store_context, decltype(&signal_protocol_store_context_destroy)> guard(raw, signal_protocol_store_context_destroy);


    // регистрируем хранилище сессий
    const signal_protocol_session_store sessionStore = sessions.toSignalStore();
    result = signal_protocol_store_context_set_session_store(guard.get(), &sessionStore);
    if (result < 0)
    {
        throw SignalException("set_session_store failed", result);
    }

    // регистрируем хранилище ключей личностей
    const signal_protocol_identity_key_store identityKeyStore = identities.toSignalStore();
    result = signal_protocol_store_context_set_identity_key_store(guard.get(), &identityKeyStore);
    if (result < 0)
    {
        throw SignalException("signal_protocol_store_context_set_identity_key_store failed", result);
    }
    
    // если прекейс не равен нуллптр, то регистрируем оба хранилища с прекейс
    if (preKeys != nullptr)
    {
        // #1
        const signal_protocol_pre_key_store preKeyStore = preKeys->toPreKeyStore();
        result = signal_protocol_store_context_set_pre_key_store(guard.get(), &preKeyStore);
        if (result < 0)
        {
            throw SignalException ("set_pre_key_store failed", result);
        }
        // #2
        const signal_protocol_signed_pre_key_store signedPreKeyStore = preKeys->toSignedPreKeyStore();
        result = signal_protocol_store_context_set_signed_pre_key_store (guard.get(), &signedPreKeyStore);
        if (result < 0)
        {
            throw SignalException ("set_signed_pre_key_store failed", result);
        }
        m_hasPreKeyStore = true;
    }

    
    // если всё ок, то забираем контекст из временной обёртки
    m_storeContext = guard.release();
}

ProtocolStoreContext::~ProtocolStoreContext()
{
    signal_protocol_store_context_destroy(m_storeContext);
}

bool ProtocolStoreContext::hasSession (const std::string &contactName, int deviceId) const
{
    // собираем адрес собеседника
    signal_protocol_address address{};

    // заполняем три поля: имя, длина имени, и девайсИд
    address.name = contactName.c_str();
    address.name_len = contactName.size();
    address.device_id = deviceId;

    return signal_protocol_session_contains_session (m_storeContext, &address) == 1;
}

void ProtocolStoreContext::savePreKeys(const GeneratedIdentity &identity)
{
    if (!m_hasPreKeyStore)
    {
        throw CryptoException ("savePreKeys: no prekey store");
    }

    if (!identity.signedPreKey)
    {
        throw CryptoException ("savePreKeys: identity is incomplete");
    }
    
    // сохраняем signedPreKey
    int result = signal_protocol_signed_pre_key_store_key(m_storeContext, identity.signedPreKey.get());
    if (result < 0)
    {
        throw SignalException ("signal_protocol_signed_pre_key_store_key failed", result);
    }

    // для oneTimePreKey
    for (const auto &preKey : identity.oneTimePreKeys)
    {
        int result = signal_protocol_pre_key_store_key(m_storeContext, preKey.get());
        if (result < 0)
        {
            throw SignalException ("pre_key_store_key failed", result);
        }
    }
}
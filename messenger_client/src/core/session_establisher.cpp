#include "core/session_establisher.h"
#include "core/signal_exception.h"
#include "session_builder.h"
#include <memory>


// делитер для билдера
namespace{
    struct SessionBuilderFree
    {
        void operator () (session_builder *builder) const{
            session_builder_free(builder);
        }
    };
}

SessionEstablisher::SessionEstablisher(signal_context *context, ProtocolStoreContext &stores)
    : m_context(context), m_stores(stores)
{
    if (m_context == nullptr)
    {
        throw CryptoException ("SessionEstablisher: context is null");
    }
}

void SessionEstablisher::establishSession(const std::string &contactName, int deviceId, session_pre_key_bundle *bundle)
{
    // проверяем аргументы
    if (bundle == nullptr)
    {
        throw CryptoException("establishSession: pre-key bundle is null");
    }

    if (contactName.empty())
    {
        throw CryptoException("establishSession: contact name is empty");
    }

    // выясняем адрес собеседника
    signal_protocol_address address {};
    address.name = contactName.c_str();
    address.name_len = contactName.size();
    address.device_id = deviceId;

    // создаём билдер
    session_builder *raw = nullptr;
    int result = session_builder_create(&raw, m_stores.get(), &address, m_context);
    if (result < 0)
    {
        throw SignalException ("session_builder_create failed", result);
    }
    // кидаем билдер в обёртку
    std::unique_ptr<session_builder, SessionBuilderFree> builder (raw);

    // результат заворачиваем в x3dh
    result = session_builder_process_pre_key_bundle (builder.get(), bundle);
    if (result < 0)
    {
        throw SignalException("session_builder_process_pre_key_bundle failed", result);
    }
}


#include "core/session_establisher.h"
#include "core/signal_exception.h"
#include "session_builder.h"
#include <memory>


// делитер для билдера
namespace{
    struct SessionBuildFree
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


    // выясняем адрес собеседника

    // создаём билдер

    // кидаем билдер в обёртку

    // результат заворачиваем в x3dh
}


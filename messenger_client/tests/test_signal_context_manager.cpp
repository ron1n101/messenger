#include "catch_amalgamated.hpp"
#include "crypto/signal_context_manager.h"
#include "curve.h"

#include <memory>
#include <type_traits>

namespace {
    // Пара ключей libsignal освобождается через signal_type_unref (как в test_signal_provider.cpp).
    struct SignalUnref
    {
        void operator()(void *object) const
        {
            signal_type_unref(static_cast<signal_type_base *>(object));
        }
    };
    using EcKeyPairPtr = std::unique_ptr<ec_key_pair, SignalUnref>;
}

// Каждый тест сам вызывает initialize: ctest запускает каждый тест отдельным процессом,
// и полагаться на то, что «предыдущий тест уже инициализировал», нельзя.

TEST_CASE("SignalContextManager is a singleton", "[context_manager]")
{
    // Два вызова instance() возвращают один и тот же объект (один адрес).
    REQUIRE(&SignalContextManager::instance() == &SignalContextManager::instance());

    // Копировать синглтон нельзя — проверяется при компиляции.
    static_assert(!std::is_copy_constructible_v<SignalContextManager>);
    static_assert(!std::is_copy_assignable_v<SignalContextManager>);
}

TEST_CASE("SignalContextManager initialize is idempotent", "[context_manager]")
{
    SignalContextManager &manager = SignalContextManager::instance();

    REQUIRE(manager.initialize());
    REQUIRE(manager.isInitialized());
    signal_context *first = manager.rawContext();
    REQUIRE(first != nullptr);

    // Повторный вызов не создаёт новый контекст.
    REQUIRE(manager.initialize());
    REQUIRE(manager.rawContext() == first);

    manager.shutdown();
}

TEST_CASE("SignalContextManager context has our crypto provider", "[context_manager]")
{
    SignalContextManager &manager = SignalContextManager::instance();
    REQUIRE(manager.initialize());

    // Генерация ключей вызывает наш randomFunc. Если провайдер не зарегистрирован,
    // библиотека упадёт на assert (как было с пропущенным random_func в 2.9.5).
    ec_key_pair *raw = nullptr;
    REQUIRE(curve_generate_key_pair(manager.rawContext(), &raw) == SG_SUCCESS);
    EcKeyPairPtr keyPair(raw);
    REQUIRE(keyPair != nullptr);

    // Ключ освобождаем ДО shutdown: он создан в этом контексте.
    keyPair.reset();
    manager.shutdown();
}

TEST_CASE("SignalContextManager shutdown is safe and allows re-initialization", "[context_manager]")
{
    SignalContextManager &manager = SignalContextManager::instance();
    REQUIRE(manager.initialize());

    manager.shutdown();
    REQUIRE_FALSE(manager.isInitialized());
    REQUIRE(manager.rawContext() == nullptr);

    // Повторный shutdown ничего не ломает.
    REQUIRE_NOTHROW(manager.shutdown());

    // После shutdown можно инициализировать заново.
    REQUIRE(manager.initialize());
    REQUIRE(manager.rawContext() != nullptr);

    manager.shutdown();
}
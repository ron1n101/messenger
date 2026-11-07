#include "signal_context_manager.h"
#include "signal_bridge.h"
#include <iostream>
#include <memory>
#include <string>

// =====================================================================
// Синглтон
// =====================================================================
SignalContextManager &SignalContextManager::instance()
{
    // создаём объект менеджера на моменте запуска кода.
    static SignalContextManager manager;
    return manager;
}

SignalContextManager::~SignalContextManager()
{
    // При завершении программы контекст уничтожится сам.
    shutdown();
}

// =====================================================================
// Создание и уничтожение
// =====================================================================
bool SignalContextManager::initialize()
{
    // ---- Шаг 1. Защищаем m_context от одновременного initialize из двух потоков.
    std::lock_guard<std::mutex> guard(m_stateMutex);

    // ---- Шаг 2. Уже создан — ничего не делаем (идемпотентность, теория 1.6).
    if (m_context != nullptr)
    {
        return true;
    }

    // ---- Шаг 3. Создаём контекст. Вторым параметром — this (теория 1.3):
    // библиотека передаст его в lockFunc/unlockFunc как user_data.
    signal_context *raw = nullptr;
    if (signal_context_create(&raw, this) != SG_SUCCESS)
    {
        return false;
    }

    // ---- Шаг 4. Временная обёртка (теория 1.7): если шаги ниже провалятся,
    // она сама уничтожит контекст при return false.
    std::unique_ptr<signal_context, decltype(&signal_context_destroy)> ctx(raw, signal_context_destroy);

    // ---- Шаг 5. Провайдер — как в makeContextWithProvider из test_signal_provider.cpp.
    signal_crypto_provider provider = SignalBridge::makeCryptoProvider();
    if (signal_context_set_crypto_provider(ctx.get(), &provider) != SG_SUCCESS)
    {
        return false;
    }

    // ---- Шаг 6. Блокировки: адреса наших статических методов.
    // signal_context_set_locking_functions(контекст, функция lock, функция unlock).
    if (signal_context_set_locking_functions(ctx.get(), lockFunc, unlockFunc) != SG_SUCCESS)
    {
        return false;
    }


    // ---- Шаг 7. Логи.
    // signal_context_set_log_function(контекст, функция log).

    
    if(signal_context_set_log_function(ctx.get(), logFunc) != SG_SUCCESS)
    {
        return false;
    }

    // ---- Шаг 8. Всё получилось — забираем контекст из обёртки.
    m_context = ctx.release();
    return true;
}

void SignalContextManager::shutdown()
{
    // ---- Шаг 1. Тот же мьютекс, что в initialize.
    // ВПИШИ: std::lock_guard ...
    std::lock_guard<std::mutex> guard(m_stateMutex);

    // ---- Шаг 2. Если контекст есть — уничтожить и обнулить указатель.
    // ЗАЧЕМ обнулять: чтобы повторный shutdown не уничтожил его второй раз,
    // а rawContext() вернул nullptr, а не адрес уже уничтоженного объекта.
    // ВПИШИ: if (m_context != nullptr) { signal_context_destroy(m_context); m_context = nullptr; }
    if (m_context != nullptr)
    {
        signal_context_destroy(m_context);
        m_context = nullptr;

    }
}

bool SignalContextManager::isInitialized() const
{
    // ВПИШИ: lock_guard + return m_context != nullptr;
    std::lock_guard<std::mutex> guard(m_stateMutex);
    return m_context != nullptr;
}

signal_context *SignalContextManager::rawContext() const
{
    // ВПИШИ: lock_guard + return m_context;
    std::lock_guard<std::mutex> guard (m_stateMutex);
    return m_context;
}

// =====================================================================
// Коллбэки для библиотеки
// =====================================================================
void SignalContextManager::lockFunc(void *user_data)
{
    // «Коробка» -> наш менеджер -> его рекурсивный мьютекс -> lock().
    static_cast<SignalContextManager *>(user_data)->m_libraryMutex.lock();
}

void SignalContextManager::unlockFunc(void *user_data)
{
    // ВПИШИ: то же, но unlock().
    static_cast<SignalContextManager *> (user_data) ->m_libraryMutex.unlock();
}

void SignalContextManager::logFunc(int level, const char *message, size_t len, void *)
{
    // ---- Шаг 1. Печатаем только ошибки и предупреждения (теория 1.8).
    // ВПИШИ: если level > SG_LOG_WARNING — return;
    if (level > SG_LOG_WARNING) return;

    // ---- Шаг 2. Печать. std::string(message, len) — строка ровно из len символов.
    const char *prefix = (level == SG_LOG_ERROR) ? "ERROR: " : "WARNING: ";
    std::cerr << "[libsignal] " << prefix << std::string(message, len) << '\n';
}
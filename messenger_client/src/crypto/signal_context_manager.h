#pragma once
#include <cstddef>
#include <mutex>
#include "signal_protocol.h"


class SignalContextManager
{
public:
    // Единственный объект (синглтон Майерса, теория 1.2).
    static SignalContextManager &instance();

    // Копировать синглтон нельзя.
    
    // запрет на копирование 
    SignalContextManager (const SignalContextManager &) = delete;
    
    // запрет оператора присваивания копированием (= delete)
    SignalContextManager  &operator = (const SignalContextManager &) = delete;
    
    // Создать контекст и настроить: провайдер, блокировки, логи.
    // Идемпотентна: повторный вызов ничего не создаёт и возвращает true.
    // Возвращает false, если что-то не удалось (контекст тогда не создаётся).
    bool initialize();

    // Уничтожить контекст. Повторный вызов безопасен.
    void shutdown();

    bool isInitialized() const;

    // Контекст для функций libsignal; nullptr, если не инициализирован.
    signal_context *rawContext() const;

private:
    // Приватный конструктор: создать объект может только instance().
    SignalContextManager() = default;
    ~SignalContextManager();

    // Коллбэки для библиотеки. static — потому что у них нет this (теория 1.3).
    // Сигнатуры — из signal_context_set_locking_functions и signal_context_set_log_function.
    static void lockFunc(void *user_data);
    static void unlockFunc(void *user_data);
    static void logFunc(int level, const char *message, size_t len, void *user_data);

    signal_context *m_context = nullptr;

    // рекурсивный мьютекс для библиотеки
    std::recursive_mutex m_libraryMutex;
    
    // обычный мьютекс для наших методов
    mutable std::mutex m_stateMutex;
};
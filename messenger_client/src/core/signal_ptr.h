#pragma once
#include <memory>
#include "signal_protocol.h"

// освобождаем объект libsignal с подсчётом ссылок
struct SignalUnref
{
    void operator ()(void *object) const
    {
        signal_type_unref(static_cast<signal_type_base *>(object));

    }
};

// создаём единый темплейт на все типы libsignal
template <typename T>
using SignalPtr = std::unique_ptr<T, SignalUnref>;

template <typename T>
SignalPtr<T> signalRef(T *object)
{
    signal_type_ref(reinterpret_cast<signal_type_base *>(object));
    return SignalPtr<T>(object);
}


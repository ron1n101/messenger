#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include "signal_protocol.h"
#include "curve.h"
#include "session_pre_key.h"
#include "core/key_generation_service.h"
#include "core/signal_ptr.h"

// Все ключи и подписи здесь — строки base64 (теория 1.3).
// Числовые поля инициализируй нулём (= 0), строки и вектор — без инициализации.

// Signed prekey в формате сервера.
struct SignedPreKeyPayload
{
    // ВПИШИ: три поля — keyId (uint32_t), publicKey (std::string), signature (std::string).
    uint32_t keyId;
    std::string publicKey;
    std::string signature;
};

// Одноразовый prekey в формате сервера.
struct OneTimePreKeyPayload
{
    // ВПИШИ: два поля — keyId и publicKey.
    uint32_t keyId;
    std::string publicKey;
};

// Наши ключи для регистрации (клиент -> сервер), теория 1.6.
struct RegisterKeysPayload
{
    // ВПИШИ: identityKeyPublic (строка), registrationId (uint32_t),
    //        signedPreKey (SignedPreKeyPayload), oneTimePreKeys (std::vector<OneTimePreKeyPayload>).
    std::string identityKeyPublic;
    uint32_t registrationId;
    SignedPreKeyPayload signedPreKey;
    std::vector<OneTimePreKeyPayload> oneTimePreKeys;
};

// Пакет собеседника для начала разговора (сервер -> клиент), теория 1.6.
struct PreKeyBundlePayload
{
    // ВПИШИ: registrationId (uint32_t = 0), deviceId (int = 1), identityKey (строка),
    //        signedPreKey (SignedPreKeyPayload),
    //        oneTimePreKey (std::optional<OneTimePreKeyPayload>) — может отсутствовать (теория 1.7).
    uint32_t registrationId = 0;
    int deviceId = 1;
    std::string identityKey;
    SignedPreKeyPayload signedPreKey;
    std::optional <OneTimePreKeyPayload> oneTimePreKey;
};

namespace KeyBundleAdapter {
    // Публичный ключ -> base64 (33 байта -> 44 символа). nullptr -> CryptoException.
    std::string encodePublicKey(const ec_public_key *key);

    // base64 -> публичный ключ. Не base64 или не ключ -> CryptoException.
    SignalPtr<ec_public_key> decodePublicKey(const std::string &base64, signal_context *context);

    // Наши ключи -> формат для регистрации. Только публичные части!
    RegisterKeysPayload toRegisterPayload(const GeneratedIdentity &identity);

    // Ответ сервера -> объект libsignal для session_builder (задача 3.5).
    SignalPtr<session_pre_key_bundle> toSessionPreKeyBundle(const PreKeyBundlePayload &payload,
                                                            signal_context *context);
}
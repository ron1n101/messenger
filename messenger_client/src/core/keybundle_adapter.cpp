#include "core/keybundle_adapter.h"
#include "crypto/base64.h"
#include "crypto/crypto_exception.h"
#include <memory>

namespace {
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;
}

std::string KeyBundleAdapter::encodePublicKey(const ec_public_key *key)
{
    // ---- Шаг 1. Без ключа -> CryptoException("encodePublicKey: key is null").
    // ВПИШИ.
    if (!key)
    {
        throw CryptoException ("encodePublicKey: key is null");
    }

    // ---- Шаг 2. Сериализация в 33 байта.
    // ec_public_key_serialize(&куда, ключ) создаёт signal_buffer; результат < 0 — ошибка.
    signal_buffer *raw = nullptr;
    // ВПИШИ: если ec_public_key_serialize(&raw, key) < 0 — CryptoException("encodePublicKey: serialize failed");
    if (ec_public_key_serialize(&raw, key) < 0)
    {
        throw CryptoException("encodePublicKey: serialize failed");
    }


    // ---- Шаг 3. Буфер — в обёртку (освободится сам).
    // ВПИШИ: SignalBufferPtr buffer(raw, signal_buffer_free);
    SignalBufferPtr buffer (raw, signal_buffer_free);

    // ---- Шаг 4. Байты из буфера -> Bytes -> base64.
    // Bytes(начало, начало + длина), где начало = signal_buffer_data(buffer.get()),
    // длина = signal_buffer_len(buffer.get()).
    // ВПИШИ: return CryptoUtils::base64Encode(...);
    return CryptoUtils::base64Encode(Bytes(signal_buffer_data(buffer.get()), signal_buffer_data(buffer.get()) + signal_buffer_len(buffer.get())));

}

SignalPtr<ec_public_key> KeyBundleAdapter::decodePublicKey(const std::string &base64, signal_context *context)
{
    // ---- Шаг 1. base64 -> байты (бросит исключение на плохой строке).
    // ВПИШИ: const Bytes bytes = ...;
    const Bytes bytes = CryptoUtils::base64Decode(base64);

    // ---- Шаг 2. Байты -> ключ. curve_decode_point сама проверит 33 байта и тип 0x05 (теория 1.5).
    // curve_decode_point(&куда, данные, длина, контекст); результат < 0 — ошибка.
    ec_public_key *raw = nullptr;
    // ВПИШИ: если < 0 — CryptoException("decodePublicKey: invalid public key");
    if(curve_decode_point(&raw, bytes.data(), bytes.size(), context ) < 0)
    {
        throw CryptoException("decodePublicKey: invalid public key");
    }
    // ---- Шаг 3. В обёртку и вернуть.
    // ВПИШИ.
    return SignalPtr<ec_public_key>(raw, SignalUnref());
}

RegisterKeysPayload KeyBundleAdapter::toRegisterPayload(const GeneratedIdentity &identity)
{
    // ---- Шаг 1. Без ключа личности или signed prekey -> CryptoException("toRegisterPayload: identity is incomplete").
    // Подсказка: SignalPtr можно проверять как bool: if (!identity.identityKeyPair || ...)
    // ВПИШИ.
    if (!identity.identityKeyPair || !identity.signedPreKey)
    {
        throw CryptoException("toRegisterPayload: identity is incomplete");
    }

    RegisterKeysPayload payload;

    // ---- Шаг 2. Ключ личности: ПУБЛИЧНАЯ часть пары.
    // ratchet_identity_key_pair_get_public(identity.identityKeyPair.get()) -> encodePublicKey.
    // ВПИШИ: payload.identityKeyPublic = ...;
    payload.identityKeyPublic = encodePublicKey(ratchet_identity_key_pair_get_public(identity.identityKeyPair.get()));
    
    // ---- Шаг 3. Registration ID — просто копия числа.
    // ВПИШИ.
    payload.registrationId = identity.registrationId;

    // ---- Шаг 4. Signed prekey: id, публичный ключ, подпись.
    const session_signed_pre_key *signedPreKey = identity.signedPreKey.get();
    // ВПИШИ: payload.signedPreKey.keyId = session_signed_pre_key_get_id(signedPreKey);
    // ВПИШИ: payload.signedPreKey.publicKey = encodePublicKey(
    //            ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signedPreKey)));


    payload.signedPreKey.keyId = session_signed_pre_key_get_id(signedPreKey);
    payload.signedPreKey.publicKey = encodePublicKey(ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signedPreKey)));

    // Подпись — это просто байты (64 штуки), не ключ: кодируем напрямую через base64Encode.
    // Указатель — session_signed_pre_key_get_signature, длина — session_signed_pre_key_get_signature_len.
    // ВПИШИ: const uint8_t *signature = ...;
    // ВПИШИ: payload.signedPreKey.signature = CryptoUtils::base64Encode(Bytes(signature, signature + <длина>));
    const uint8_t *signature = session_signed_pre_key_get_signature(signedPreKey);
    payload.signedPreKey.signature = CryptoUtils::base64Encode(Bytes(signature, signature + session_signed_pre_key_get_signature_len(signedPreKey)));
    
    // ---- Шаг 5. Одноразовые prekeys.
    // ВПИШИ: payload.oneTimePreKeys.reserve(<сколько их в identity>);
    payload.oneTimePreKeys.reserve(identity.oneTimePreKeys.size());

    for (const auto &preKey : identity.oneTimePreKeys)
    {
        OneTimePreKeyPayload item;
        // ВПИШИ: item.keyId = session_pre_key_get_id(preKey.get());
        // ВПИШИ: item.publicKey = encodePublicKey(ec_key_pair_get_public(session_pre_key_get_key_pair(preKey.get())));
        // ВПИШИ: положить item в payload.oneTimePreKeys.
        item.keyId = session_pre_key_get_id(preKey.get());
        item.publicKey = encodePublicKey(ec_key_pair_get_public(session_pre_key_get_key_pair(preKey.get())));
        payload.oneTimePreKeys.push_back(item);
    }

    return payload;
}

SignalPtr<session_pre_key_bundle> KeyBundleAdapter::toSessionPreKeyBundle(
    const PreKeyBundlePayload &payload, signal_context *context)
{
    // ---- Шаг 1. Без контекста -> CryptoException("toSessionPreKeyBundle: context is null").
    // ВПИШИ.
    if (!context)
    {
        throw CryptoException("toSessionPreKeyBundle: context is null");
    }
    // ---- Шаг 2. Декодируем обязательные части. Любая ошибка -> исключение из decodePublicKey/base64Decode.
    // ВПИШИ: SignalPtr<ec_public_key> identityKey = decodePublicKey(payload.identityKey, context);
    // ВПИШИ: SignalPtr<ec_public_key> signedPreKey = decodePublicKey(<публичный ключ signed prekey>, context);
    // ВПИШИ: const Bytes signature = CryptoUtils::base64Decode(<подпись signed prekey>);
    SignalPtr<ec_public_key> identityKey = decodePublicKey(payload.identityKey, context);
    SignalPtr<ec_public_key> signedPreKey = decodePublicKey(payload.signedPreKey.publicKey, context);
    const Bytes signature = CryptoUtils::base64Decode(payload.signedPreKey.signature);

    // ---- Шаг 3. Одноразовый ключ — только если он есть (теория 1.7).
    // Если нет: указатель остаётся пустым, id = 0 — так библиотека понимает «без одноразового ключа».
    SignalPtr<ec_public_key> oneTimePreKey;
    uint32_t oneTimePreKeyId = 0;


    // ВПИШИ: if (payload.oneTimePreKey) { oneTimePreKey = decodePublicKey(...->publicKey, context);
    //                                    oneTimePreKeyId = ...->keyId; }

    if (payload.oneTimePreKey)
    {
        oneTimePreKey = decodePublicKey(payload.oneTimePreKey ->publicKey, context);
        oneTimePreKeyId = payload.oneTimePreKey->keyId;
    }
    // ---- Шаг 4. Собираем пакет. Параметры session_pre_key_bundle_create по порядку:
    //   &куда, registration_id, device_id,
    //   pre_key_id, pre_key_public (одноразовый; .get() — может быть nullptr),
    //   signed_pre_key_id, signed_pre_key_public,
    //   signature.data(), signature.size(),
    //   identity_key.
    // Ключи передаём через .get(): пакет сам «запишется» на них (теория 1.8).
    session_pre_key_bundle *raw = nullptr;
    // ВПИШИ: если session_pre_key_bundle_create(...) < 0 —
    //        CryptoException("toSessionPreKeyBundle: session_pre_key_bundle_create failed");

    if (session_pre_key_bundle_create(&raw, payload.registrationId, payload.deviceId, oneTimePreKeyId, oneTimePreKey.get(),
                                      payload.signedPreKey.keyId, signedPreKey.get(),
                                      signature.data(), signature.size(),
                                      identityKey.get()) < 0)
    {
        throw CryptoException("toSessionPreKeyBundle: session_pre_key_bundle_create failed");
    }
    // ---- Шаг 5. В обёртку и вернуть.
    // ВПИШИ.
    return SignalPtr<session_pre_key_bundle>(raw, SignalUnref());
}
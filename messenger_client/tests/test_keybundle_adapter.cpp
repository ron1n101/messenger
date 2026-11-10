#include "catch_amalgamated.hpp"
#include "core/keybundle_adapter.h"
#include "core/key_generation_service.h"
#include "crypto/base64.h"
#include "crypto/crypto_exception.h"
#include "crypto/signal_context_manager.h"
#include "crypto/types.h"

#include "curve.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;

    signal_context *appContext()
    {
        REQUIRE(SignalContextManager::instance().initialize());
        return SignalContextManager::instance().rawContext();
    }

    Bytes bytesFromString(const std::string &text) { return Bytes(text.begin(), text.end()); }

    // Публичный ключ -> 33 байта (для сравнения с тем, что пришло через base64).
    Bytes serializePublicKey(const ec_public_key *key)
    {
        signal_buffer *raw = nullptr;
        REQUIRE(ec_public_key_serialize(&raw, key) == SG_SUCCESS);
        SignalBufferPtr buffer(raw, signal_buffer_free);
        const uint8_t *begin = signal_buffer_data(buffer.get());
        return Bytes(begin, begin + signal_buffer_len(buffer.get()));
    }

    // «Сервер понарошку»: из того, что Боб загрузил при регистрации,
    // собирает ответ для Алисы — как это будет делать настоящий сервер в Фазе 5.
    PreKeyBundlePayload simulateServerResponse(const RegisterKeysPayload &uploaded, bool withOneTimeKey)
    {
        PreKeyBundlePayload response;
        response.registrationId = uploaded.registrationId;
        response.deviceId = 1;
        response.identityKey = uploaded.identityKeyPublic;
        response.signedPreKey = uploaded.signedPreKey;
        if (withOneTimeKey)
        {
            response.oneTimePreKey = uploaded.oneTimePreKeys.front();
        }
        return response;
    }
}

// =====================================================================
// 1. Base64 — эталоны из RFC 4648, раздел 10
// =====================================================================
TEST_CASE("base64Encode matches RFC 4648 test vectors", "[base64]")
{
    const std::vector<std::pair<std::string, std::string>> vectors = {
        {"", ""},
        {"f", "Zg=="},
        {"fo", "Zm8="},
        {"foo", "Zm9v"},
        {"foob", "Zm9vYg=="},
        {"fooba", "Zm9vYmE="},
        {"foobar", "Zm9vYmFy"},
    };

    for (const auto &[plain, encoded] : vectors)
    {
        REQUIRE(CryptoUtils::base64Encode(bytesFromString(plain)) == encoded);
        REQUIRE(CryptoUtils::base64Decode(encoded) == bytesFromString(plain));
    }
}

TEST_CASE("base64 round-trips binary data including zeros and 0xFF", "[base64]")
{
    // Все 256 значений байта: проверка, что «невидимые» байты не теряются.
    Bytes allBytes(256);
    for (size_t i = 0; i < allBytes.size(); ++i)
    {
        allBytes[i] = static_cast<uint8_t>(i);
    }
    REQUIRE(CryptoUtils::base64Decode(CryptoUtils::base64Encode(allBytes)) == allBytes);

    // Без переносов строк: ключ уходит в JSON одной строкой.
    const std::string encoded = CryptoUtils::base64Encode(allBytes);
    REQUIRE(encoded.find('\n') == std::string::npos);
}

TEST_CASE("base64Decode rejects malformed input", "[base64][negative]")
{
    REQUIRE_THROWS_AS(CryptoUtils::base64Decode("Zm9"), CryptoException);        // длина не кратна 4
    REQUIRE_THROWS_AS(CryptoUtils::base64Decode("Zm9v!"), CryptoException);      // длина 5
    REQUIRE_THROWS_AS(CryptoUtils::base64Decode("Zm!v"), CryptoException);       // недопустимый символ
    REQUIRE_THROWS_AS(CryptoUtils::base64Decode("Zm 9"), CryptoException);       // пробел внутри
    REQUIRE_THROWS_AS(CryptoUtils::base64Decode("Z=9v"), CryptoException);       // '=' не в конце
    REQUIRE_THROWS_AS(CryptoUtils::base64Decode("Zm9v\nZm9v"), CryptoException); // перенос строки
}

// =====================================================================
// 2. Публичный ключ <-> base64
// =====================================================================
TEST_CASE("Public key survives base64 round-trip", "[keybundle]")
{
    KeyGenerationService service(appContext());
    SignalPtr<ratchet_identity_key_pair> identity = service.generateIdentityKeyPair();
    const ec_public_key *original = ratchet_identity_key_pair_get_public(identity.get());

    const std::string encoded = KeyBundleAdapter::encodePublicKey(original);
    // 33 байта -> 44 символа base64 (33 делится на 3, поэтому без '=').
    REQUIRE(encoded.size() == 44);

    SignalPtr<ec_public_key> decoded = KeyBundleAdapter::decodePublicKey(encoded, appContext());
    REQUIRE(ec_public_key_compare(original, decoded.get()) == 0);
}

TEST_CASE("decodePublicKey rejects wrong length and wrong key type", "[keybundle][negative]")
{
    // 32 байта вместо 33 — нет байта типа.
    const std::string tooShort = CryptoUtils::base64Encode(Bytes(32, 0x01));
    REQUIRE_THROWS_AS(KeyBundleAdapter::decodePublicKey(tooShort, appContext()), CryptoException);

    // 33 байта, но первый байт не 0x05.
    Bytes wrongType(33, 0x01);
    wrongType[0] = 0x07;
    REQUIRE_THROWS_AS(KeyBundleAdapter::decodePublicKey(CryptoUtils::base64Encode(wrongType), appContext()),
                      CryptoException);

    // Не base64.
    REQUIRE_THROWS_AS(KeyBundleAdapter::decodePublicKey("not base64!", appContext()), CryptoException);

    // encodePublicKey без ключа.
    REQUIRE_THROWS_AS(KeyBundleAdapter::encodePublicKey(nullptr), CryptoException);
}

// =====================================================================
// 3. Ключи для регистрации
// =====================================================================
TEST_CASE("toRegisterPayload carries every public key, id and signature", "[keybundle]")
{
    KeyGenerationService service(appContext());
    const GeneratedIdentity identity = service.generateNewIdentity(5);

    const RegisterKeysPayload payload = KeyBundleAdapter::toRegisterPayload(identity);

    // Ключ личности: тот же, что в identity.
    SignalPtr<ec_public_key> identityKey = KeyBundleAdapter::decodePublicKey(payload.identityKeyPublic, appContext());
    REQUIRE(ec_public_key_compare(identityKey.get(),
                                  ratchet_identity_key_pair_get_public(identity.identityKeyPair.get())) == 0);

    REQUIRE(payload.registrationId == identity.registrationId);

    // Signed prekey: id, публичный ключ и подпись.
    const session_signed_pre_key *signedPreKey = identity.signedPreKey.get();
    REQUIRE(payload.signedPreKey.keyId == session_signed_pre_key_get_id(signedPreKey));
    SignalPtr<ec_public_key> signedPublic =
        KeyBundleAdapter::decodePublicKey(payload.signedPreKey.publicKey, appContext());
    REQUIRE(ec_public_key_compare(signedPublic.get(),
                                  ec_key_pair_get_public(session_signed_pre_key_get_key_pair(signedPreKey))) == 0);

    const Bytes signature = CryptoUtils::base64Decode(payload.signedPreKey.signature);
    REQUIRE(signature.size() == 64);

    // Главное: подпись, пришедшая через base64, проверяется ключом личности, пришедшим через base64.
    // Ровно так сделает собеседник, получив наш пакет с сервера.
    const Bytes signedMessage = serializePublicKey(signedPublic.get());
    REQUIRE(curve_verify_signature(identityKey.get(),
                                   signedMessage.data(), signedMessage.size(),
                                   signature.data(), signature.size()) == 1);

    // Одноразовые prekeys: все пять, с правильными id и уникальными ключами.
    REQUIRE(payload.oneTimePreKeys.size() == 5);
    std::set<std::string> uniqueKeys;
    for (size_t i = 0; i < payload.oneTimePreKeys.size(); ++i)
    {
        REQUIRE(payload.oneTimePreKeys[i].keyId == session_pre_key_get_id(identity.oneTimePreKeys[i].get()));
        uniqueKeys.insert(payload.oneTimePreKeys[i].publicKey);
    }
    REQUIRE(uniqueKeys.size() == 5);
}

TEST_CASE("toRegisterPayload contains no private key material", "[keybundle][security]")
{
    KeyGenerationService service(appContext());
    const GeneratedIdentity identity = service.generateNewIdentity(1);
    const RegisterKeysPayload payload = KeyBundleAdapter::toRegisterPayload(identity);

    // Сериализуем приватный ключ личности и убеждаемся, что его base64 нигде не встречается.
    signal_buffer *raw = nullptr;
    REQUIRE(ec_private_key_serialize(&raw, ratchet_identity_key_pair_get_private(identity.identityKeyPair.get()))
            == SG_SUCCESS);
    std::unique_ptr<signal_buffer, decltype(&signal_buffer_bzero_free)> privateKey(raw, signal_buffer_bzero_free);
    const uint8_t *begin = signal_buffer_data(privateKey.get());
    const std::string privateBase64 =
        CryptoUtils::base64Encode(Bytes(begin, begin + signal_buffer_len(privateKey.get())));

    REQUIRE(payload.identityKeyPublic != privateBase64);
    REQUIRE(payload.signedPreKey.publicKey != privateBase64);
    REQUIRE(payload.oneTimePreKeys.front().publicKey != privateBase64);
}

TEST_CASE("toRegisterPayload rejects an incomplete identity", "[keybundle][negative]")
{
    GeneratedIdentity empty;   // все указатели пустые
    REQUIRE_THROWS_AS(KeyBundleAdapter::toRegisterPayload(empty), CryptoException);
}

// =====================================================================
// 4. Ответ сервера -> session_pre_key_bundle библиотеки
// =====================================================================
TEST_CASE("Server response becomes a libsignal pre-key bundle", "[keybundle]")
{
    KeyGenerationService service(appContext());
    const GeneratedIdentity bob = service.generateNewIdentity(3);
    const RegisterKeysPayload uploaded = KeyBundleAdapter::toRegisterPayload(bob);

    const PreKeyBundlePayload response = simulateServerResponse(uploaded, true);
    SignalPtr<session_pre_key_bundle> bundle = KeyBundleAdapter::toSessionPreKeyBundle(response, appContext());
    REQUIRE(bundle != nullptr);

    REQUIRE(session_pre_key_bundle_get_registration_id(bundle.get()) == bob.registrationId);
    REQUIRE(session_pre_key_bundle_get_device_id(bundle.get()) == 1);

    REQUIRE(ec_public_key_compare(session_pre_key_bundle_get_identity_key(bundle.get()),
                                  ratchet_identity_key_pair_get_public(bob.identityKeyPair.get())) == 0);

    REQUIRE(session_pre_key_bundle_get_signed_pre_key_id(bundle.get()) == uploaded.signedPreKey.keyId);
    REQUIRE(ec_public_key_compare(
                session_pre_key_bundle_get_signed_pre_key(bundle.get()),
                ec_key_pair_get_public(session_signed_pre_key_get_key_pair(bob.signedPreKey.get()))) == 0);
    REQUIRE(signal_buffer_len(session_pre_key_bundle_get_signed_pre_key_signature(bundle.get())) == 64);

    // Одноразовый ключ — первый из загруженных.
    REQUIRE(session_pre_key_bundle_get_pre_key_id(bundle.get()) == uploaded.oneTimePreKeys.front().keyId);
    REQUIRE(ec_public_key_compare(
                session_pre_key_bundle_get_pre_key(bundle.get()),
                ec_key_pair_get_public(session_pre_key_get_key_pair(bob.oneTimePreKeys.front().get()))) == 0);
}

TEST_CASE("Pre-key bundle can be built without a one-time prekey", "[keybundle][edge]")
{
    // Когда одноразовые ключи у Боба на сервере закончились, сервер присылает пакет без них.
    KeyGenerationService service(appContext());
    const GeneratedIdentity bob = service.generateNewIdentity(1);
    const PreKeyBundlePayload response =
        simulateServerResponse(KeyBundleAdapter::toRegisterPayload(bob), false);

    SignalPtr<session_pre_key_bundle> bundle = KeyBundleAdapter::toSessionPreKeyBundle(response, appContext());
    REQUIRE(bundle != nullptr);
    REQUIRE(session_pre_key_bundle_get_pre_key(bundle.get()) == nullptr);
    REQUIRE(session_pre_key_bundle_get_pre_key_id(bundle.get()) == 0);
}

TEST_CASE("toSessionPreKeyBundle rejects broken server data", "[keybundle][negative]")
{
    KeyGenerationService service(appContext());
    const GeneratedIdentity bob = service.generateNewIdentity(1);
    const PreKeyBundlePayload good = simulateServerResponse(KeyBundleAdapter::toRegisterPayload(bob), true);

    PreKeyBundlePayload badIdentity = good;
    badIdentity.identityKey = "AAAA";   // валидный base64, но не ключ
    REQUIRE_THROWS_AS(KeyBundleAdapter::toSessionPreKeyBundle(badIdentity, appContext()), CryptoException);

    PreKeyBundlePayload badSignature = good;
    badSignature.signedPreKey.signature = "%%%%";   // не base64
    REQUIRE_THROWS_AS(KeyBundleAdapter::toSessionPreKeyBundle(badSignature, appContext()), CryptoException);

    PreKeyBundlePayload badOneTime = good;
    badOneTime.oneTimePreKey->publicKey = "Zm9v";   // 3 байта, не ключ
    REQUIRE_THROWS_AS(KeyBundleAdapter::toSessionPreKeyBundle(badOneTime, appContext()), CryptoException);

    REQUIRE_THROWS_AS(KeyBundleAdapter::toSessionPreKeyBundle(good, nullptr), CryptoException);
}
#include "catch_amalgamated.hpp"
#include "core/key_generation_service.h"
#include "crypto/signal_context_manager.h"
#include "crypto/crypto_exception.h"
#include "crypto/types.h"

#include "curve.h"           // ec_public_key_serialize, curve_verify_signature

#include <memory>
#include <set>

namespace {
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;
    // Для буферов с секретами: затирает перед освобождением.
    using SecretBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_bzero_free)>;

    // Общий контекст приложения (задача 3.2).
    signal_context *appContext()
    {
        REQUIRE(SignalContextManager::instance().initialize());
        return SignalContextManager::instance().rawContext();
    }

    // Публичный ключ -> 33 байта (0x05 + 32 байта Curve25519).
    Bytes serializePublicKey(const ec_public_key *key)
    {
        signal_buffer *raw = nullptr;
        REQUIRE(ec_public_key_serialize(&raw, key) == SG_SUCCESS);
        SignalBufferPtr buffer(raw, signal_buffer_free);
        const uint8_t *begin = signal_buffer_data(buffer.get());
        return Bytes(begin, begin + signal_buffer_len(buffer.get()));
    }

    // Проверка подписи signed prekey: подписан ли его публичный ключ ключом личности identity.
    // Так же это проверит собеседник в X3DH (задача 3.5).
    bool signedPreKeySignatureIsValid(const ratchet_identity_key_pair *identity,
                                      const session_signed_pre_key *signedPreKey)
    {
        const ec_key_pair *pair = session_signed_pre_key_get_key_pair(signedPreKey);
        const Bytes signedMessage = serializePublicKey(ec_key_pair_get_public(pair));

        // curve_verify_signature: 1 — подпись верна, 0 — неверна, < 0 — ошибка.
        return curve_verify_signature(ratchet_identity_key_pair_get_public(identity),
                                      signedMessage.data(), signedMessage.size(),
                                      session_signed_pre_key_get_signature(signedPreKey),
                                      session_signed_pre_key_get_signature_len(signedPreKey)) == 1;
    }
}

// =====================================================================
// 1. Ключ личности
// =====================================================================
TEST_CASE("Identity key pair is valid and survives serialization", "[keygen]")
{
    KeyGenerationService service(appContext());
    SignalPtr<ratchet_identity_key_pair> identity = service.generateIdentityKeyPair();
    REQUIRE(identity != nullptr);

    // Публичный ключ: 33 байта, первый — тип ключа 0x05 (Curve25519).
    const Bytes publicKey = serializePublicKey(ratchet_identity_key_pair_get_public(identity.get()));
    REQUIRE(publicKey.size() == 33);
    REQUIRE(publicKey[0] == 0x05);

    // Пара -> байты -> пара. Так ключ будет храниться в локальной БД (Фаза 7).
    // В буфере приватный ключ, поэтому освобождаем с затиранием.
    signal_buffer *rawSerialized = nullptr;
    REQUIRE(ratchet_identity_key_pair_serialize(&rawSerialized, identity.get()) == SG_SUCCESS);
    SecretBufferPtr serialized(rawSerialized, signal_buffer_bzero_free);

    ratchet_identity_key_pair *rawRestored = nullptr;
    REQUIRE(ratchet_identity_key_pair_deserialize(&rawRestored,
                                                  signal_buffer_data(serialized.get()),
                                                  signal_buffer_len(serialized.get()),
                                                  appContext()) == SG_SUCCESS);
    SignalPtr<ratchet_identity_key_pair> restored(rawRestored);

    // Восстановленная пара совпадает с исходной: и публичная, и приватная часть.
    REQUIRE(serializePublicKey(ratchet_identity_key_pair_get_public(restored.get())) == publicKey);
    REQUIRE(ec_private_key_compare(ratchet_identity_key_pair_get_private(identity.get()),
                                   ratchet_identity_key_pair_get_private(restored.get())) == 0);
}

TEST_CASE("Two identity key pairs are different", "[keygen]")
{
    KeyGenerationService service(appContext());
    SignalPtr<ratchet_identity_key_pair> first = service.generateIdentityKeyPair();
    SignalPtr<ratchet_identity_key_pair> second = service.generateIdentityKeyPair();

    REQUIRE(serializePublicKey(ratchet_identity_key_pair_get_public(first.get())) !=
            serializePublicKey(ratchet_identity_key_pair_get_public(second.get())));
}

// =====================================================================
// 2. Registration ID
// =====================================================================
TEST_CASE("Registration ID is in the allowed range", "[keygen]")
{
    KeyGenerationService service(appContext());
    std::set<uint32_t> seen;

    for (int attempt = 0; attempt < 20; ++attempt)
    {
        const uint32_t registrationId = service.generateRegistrationId();
        // Обычный диапазон libsignal: от 1 до 16380.
        REQUIRE(registrationId >= 1);
        REQUIRE(registrationId <= 16380);
        seen.insert(registrationId);
    }

    // 20 случайных чисел из 16380 не могут все совпасть.
    REQUIRE(seen.size() > 1);
}

// =====================================================================
// 3. Одноразовые prekeys
// =====================================================================
TEST_CASE("One-time prekeys have sequential ids and unique keys", "[keygen]")
{
    KeyGenerationService service(appContext());
    const std::vector<SignalPtr<session_pre_key>> preKeys = service.generatePreKeys(1, 100);
    REQUIRE(preKeys.size() == 100);

    std::set<Bytes> publicKeys;
    for (size_t i = 0; i < preKeys.size(); ++i)
    {
        // id идут подряд, начиная с firstId = 1.
        REQUIRE(session_pre_key_get_id(preKeys[i].get()) == i + 1);

        const ec_key_pair *pair = session_pre_key_get_key_pair(preKeys[i].get());
        publicKeys.insert(serializePublicKey(ec_key_pair_get_public(pair)));
    }

    // Все 100 публичных ключей разные (set хранит только уникальные значения).
    REQUIRE(publicKeys.size() == 100);
}

TEST_CASE("Prekey ids wrap around after the maximum", "[keygen][edge]")
{
    KeyGenerationService service(appContext());

    // Максимальный id — 0xFFFFFE. После него нумерация начинается с 1.
    const std::vector<SignalPtr<session_pre_key>> preKeys = service.generatePreKeys(0xFFFFFD, 3);
    REQUIRE(preKeys.size() == 3);
    REQUIRE(session_pre_key_get_id(preKeys[0].get()) == 0xFFFFFD);
    REQUIRE(session_pre_key_get_id(preKeys[1].get()) == 0xFFFFFE);
    REQUIRE(session_pre_key_get_id(preKeys[2].get()) == 1);
}

TEST_CASE("generatePreKeys rejects bad arguments", "[keygen][negative]")
{
    KeyGenerationService service(appContext());

    REQUIRE_THROWS_AS(service.generatePreKeys(1, 0), CryptoException);          // ноль ключей
    REQUIRE_THROWS_AS(service.generatePreKeys(0, 5), CryptoException);          // id 0 не бывает
    REQUIRE_THROWS_AS(service.generatePreKeys(0xFFFFFF, 5), CryptoException);   // больше максимума
}

// =====================================================================
// 4. Signed prekey
// =====================================================================
TEST_CASE("Signed prekey is signed by the identity key", "[keygen]")
{
    KeyGenerationService service(appContext());
    SignalPtr<ratchet_identity_key_pair> identity = service.generateIdentityKeyPair();
    SignalPtr<ratchet_identity_key_pair> stranger = service.generateIdentityKeyPair();

    SignalPtr<session_signed_pre_key> signedPreKey = service.generateSignedPreKey(identity.get(), 42);
    REQUIRE(signedPreKey != nullptr);

    REQUIRE(session_signed_pre_key_get_id(signedPreKey.get()) == 42);
    REQUIRE(session_signed_pre_key_get_signature_len(signedPreKey.get()) == 64);

    // Время создания — в миллисекундах; 1 700 000 000 000 мс — это ноябрь 2023.
    REQUIRE(session_signed_pre_key_get_timestamp(signedPreKey.get()) > 1700000000000ULL);

    // Подпись сходится с ключом владельца и НЕ сходится с чужим.
    REQUIRE(signedPreKeySignatureIsValid(identity.get(), signedPreKey.get()));
    REQUIRE_FALSE(signedPreKeySignatureIsValid(stranger.get(), signedPreKey.get()));
}

TEST_CASE("generateSignedPreKey rejects a null identity", "[keygen][negative]")
{
    KeyGenerationService service(appContext());
    REQUIRE_THROWS_AS(service.generateSignedPreKey(nullptr, 1), CryptoException);
}

// =====================================================================
// 5. Всё вместе
// =====================================================================
TEST_CASE("generateNewIdentity produces a complete key set", "[keygen]")
{
    KeyGenerationService service(appContext());
    const GeneratedIdentity identity = service.generateNewIdentity(10);

    REQUIRE(identity.identityKeyPair != nullptr);
    REQUIRE(identity.registrationId >= 1);
    REQUIRE(identity.signedPreKey != nullptr);
    REQUIRE(identity.oneTimePreKeys.size() == 10);

    // Signed prekey подписан именно ключом личности этого набора.
    REQUIRE(signedPreKeySignatureIsValid(identity.identityKeyPair.get(), identity.signedPreKey.get()));
}

TEST_CASE("KeyGenerationService rejects a null context", "[keygen][negative]")
{
    REQUIRE_THROWS_AS(KeyGenerationService(nullptr), CryptoException);
}
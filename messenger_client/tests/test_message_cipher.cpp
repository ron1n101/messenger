#include "catch_amalgamated.hpp"
#include "core/message_cipher.h"
#include "core/session_establisher.h"
#include "core/protocol_store_context.h"
#include "core/signal_exception.h"
#include "core/key_generation_service.h"
#include "core/keybundle_adapter.h"
#include "core/store/in_memory_session_store.h"
#include "core/store/in_memory_identity_store.h"
#include "core/store/in_memory_prekey_store.h"
#include "crypto/signal_context_manager.h"
#include "crypto/crypto_exception.h"

#include <memory>
#include <string>

// Полный диалог Алисы и Боба через настоящий Signal Protocol:
// X3DH (session_builder) + Double Ratchet (session_cipher).

namespace {
    signal_context *appContext()
    {
        REQUIRE(SignalContextManager::instance().initialize());
        return SignalContextManager::instance().rawContext();
    }

    Bytes text(const std::string &value) { return Bytes(value.begin(), value.end()); }

    // Один участник: ключи + все четыре хранилища + контекст хранилищ + шифровальщик.
    // Порядок полей важен: всё, на что ссылается контекст хранилищ, объявлено ДО него
    // и поэтому уничтожается ПОСЛЕ него (теория 1.4 из 3.5b).
    struct Party
    {
        std::string name;
        GeneratedIdentity identity;
        InMemorySessionStore sessions;
        InMemoryPreKeyStore preKeys;
        std::unique_ptr<InMemoryIdentityStore> identities;
        std::unique_ptr<ProtocolStoreContext> stores;
        std::unique_ptr<MessageCipher> cipher;

        Party(const std::string &partyName, KeyGenerationService &generator, unsigned int preKeyCount)
            : name(partyName), identity(generator.generateNewIdentity(preKeyCount))
        {
            identities = std::make_unique<InMemoryIdentityStore>(identity.identityKeyPair.get(), identity.registrationId);
            stores = std::make_unique<ProtocolStoreContext>(appContext(), sessions, *identities, &preKeys);
            // Свои prekeys кладём в хранилище — так их потом найдёт session_cipher на стороне получателя.
            stores->savePreKeys(identity);
            cipher = std::make_unique<MessageCipher>(appContext(), *stores);
        }

        // Ответ «сервера» с пакетом этого участника (как в 3.4).
        PreKeyBundlePayload bundlePayload(bool withOneTimeKey) const
        {
            const RegisterKeysPayload uploaded = KeyBundleAdapter::toRegisterPayload(identity);
            PreKeyBundlePayload response;
            response.registrationId = uploaded.registrationId;
            response.identityKey = uploaded.identityKeyPublic;
            response.signedPreKey = uploaded.signedPreKey;
            if (withOneTimeKey)
            {
                response.oneTimePreKey = uploaded.oneTimePreKeys.front();
            }
            return response;
        }

        // X3DH: начать сессию с other по его пакету (задача 3.5b).
        void startSessionWith(const Party &other, bool withOneTimeKey = true)
        {
            SignalPtr<session_pre_key_bundle> bundle =
                KeyBundleAdapter::toSessionPreKeyBundle(other.bundlePayload(withOneTimeKey), appContext());
            SessionEstablisher establisher(appContext(), *stores);
            establisher.establishSession(other.name, 1, bundle.get());
        }

        EncryptedMessage send(const Party &to, const std::string &message)
        {
            return cipher->encrypt(to.name, 1, text(message));
        }

        std::string receive(const Party &from, const EncryptedMessage &message)
        {
            const Bytes plain = cipher->decrypt(from.name, 1, message);
            return std::string(plain.begin(), plain.end());
        }
    };
}

// =====================================================================
// 1. Хранилище prekeys
// =====================================================================
TEST_CASE("PreKey store follows the libsignal contracts", "[prekey_store]")
{
    InMemoryPreKeyStore preKeys;
    signal_protocol_pre_key_store store = preKeys.toPreKeyStore();
    REQUIRE(store.user_data == &preKeys);
    REQUIRE(store.destroy_func == nullptr);

    // Не нашли -> SG_ERR_INVALID_KEY_ID (а не 0, как у сессий!).
    signal_buffer *record = nullptr;
    REQUIRE(store.load_pre_key(&record, 7, store.user_data) == SG_ERR_INVALID_KEY_ID);
    REQUIRE(record == nullptr);
    REQUIRE(store.contains_pre_key(7, store.user_data) == 0);

    Bytes data = {1, 2, 3};
    REQUIRE(store.store_pre_key(7, data.data(), data.size(), store.user_data) == SG_SUCCESS);
    REQUIRE(store.contains_pre_key(7, store.user_data) == 1);

    // Нашли -> SG_SUCCESS (0) и новый буфер.
    REQUIRE(store.load_pre_key(&record, 7, store.user_data) == SG_SUCCESS);
    std::unique_ptr<signal_buffer, decltype(&signal_buffer_bzero_free)> loaded(record, signal_buffer_bzero_free);
    REQUIRE(Bytes(signal_buffer_data(loaded.get()), signal_buffer_data(loaded.get()) + signal_buffer_len(loaded.get())) == data);

    REQUIRE(store.remove_pre_key(7, store.user_data) == SG_SUCCESS);
    REQUIRE(store.contains_pre_key(7, store.user_data) == 0);
    // Удалить несуществующий — тоже успех.
    REQUIRE(store.remove_pre_key(7, store.user_data) == SG_SUCCESS);
}

TEST_CASE("Signed prekeys are kept separately from one-time prekeys", "[prekey_store]")
{
    InMemoryPreKeyStore preKeys;
    signal_protocol_pre_key_store oneTime = preKeys.toPreKeyStore();
    signal_protocol_signed_pre_key_store signedStore = preKeys.toSignedPreKeyStore();
    REQUIRE(signedStore.user_data == &preKeys);

    Bytes data = {9};
    REQUIRE(signedStore.store_signed_pre_key(1, data.data(), data.size(), signedStore.user_data) == SG_SUCCESS);
    REQUIRE(signedStore.contains_signed_pre_key(1, signedStore.user_data) == 1);

    // Номер 1 у signed prekey и номер 1 у одноразового — РАЗНЫЕ ключи.
    REQUIRE(oneTime.contains_pre_key(1, oneTime.user_data) == 0);
    REQUIRE(preKeys.signedPreKeyCount() == 1);
    REQUIRE(preKeys.preKeyCount() == 0);
}

TEST_CASE("savePreKeys puts the generated keys into the store", "[prekey_store]")
{
    KeyGenerationService generator(appContext());
    Party bob("bob", generator, 5);
    REQUIRE(bob.preKeys.preKeyCount() == 5);
    REQUIRE(bob.preKeys.signedPreKeyCount() == 1);
}

// =====================================================================
// 2. Диалог
// =====================================================================
TEST_CASE("Alice and Bob exchange messages end-to-end", "[cipher]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 3);

    alice.startSessionWith(bob);

    // Первое сообщение Алисы — особое: PreKeyWhisperMessage (тип 3).
    const EncryptedMessage first = alice.send(bob, "Hi Bob!");
    REQUIRE(first.type == MessageCipher::kPreKeyMessage);
    REQUIRE(first.body != text("Hi Bob!"));

    // У Боба сессии ещё нет — её создаст расшифровка первого сообщения.
    REQUIRE_FALSE(bob.stores->hasSession("alice", 1));
    REQUIRE(bob.receive(alice, first) == "Hi Bob!");
    REQUIRE(bob.stores->hasSession("alice", 1));

    // Одноразовый prekey, которым воспользовалась Алиса, у Боба удалён.
    REQUIRE(bob.preKeys.preKeyCount() == 2);

    // Ответ Боба — уже обычное сообщение (тип 2).
    const EncryptedMessage reply = bob.send(alice, "Hi Alice!");
    REQUIRE(reply.type == MessageCipher::kSignalMessage);
    REQUIRE(alice.receive(bob, reply) == "Hi Alice!");

    // Получив ответ, Алиса тоже переходит на обычные сообщения.
    const EncryptedMessage next = alice.send(bob, "How are you?");
    REQUIRE(next.type == MessageCipher::kSignalMessage);
    REQUIRE(bob.receive(alice, next) == "How are you?");
}

TEST_CASE("Session works without a one-time prekey", "[cipher]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);

    alice.startSessionWith(bob, false);
    const EncryptedMessage first = alice.send(bob, "no one-time key");
    REQUIRE(bob.receive(alice, first) == "no one-time key");
    // Одноразовый ключ Боба не тронут.
    REQUIRE(bob.preKeys.preKeyCount() == 1);
}

TEST_CASE("Every message has a different ciphertext", "[cipher]")
{
    // Double Ratchet: каждое сообщение шифруется НОВЫМ ключом.
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);
    alice.startSessionWith(bob);

    const EncryptedMessage one = alice.send(bob, "same text");
    const EncryptedMessage two = alice.send(bob, "same text");
    REQUIRE(one.body != two.body);

    REQUIRE(bob.receive(alice, one) == "same text");
    REQUIRE(bob.receive(alice, two) == "same text");
}

TEST_CASE("Messages delivered out of order are still decrypted", "[cipher]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);
    alice.startSessionWith(bob);

    const EncryptedMessage first = alice.send(bob, "1");
    REQUIRE(bob.receive(alice, first) == "1");
    const EncryptedMessage reply = bob.send(alice, "ok");
    REQUIRE(alice.receive(bob, reply) == "ok");

    const EncryptedMessage second = alice.send(bob, "2");
    const EncryptedMessage third = alice.send(bob, "3");
    // Третье пришло раньше второго.
    REQUIRE(bob.receive(alice, third) == "3");
    REQUIRE(bob.receive(alice, second) == "2");
}

TEST_CASE("Replayed message is rejected", "[cipher][security]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);
    alice.startSessionWith(bob);

    const EncryptedMessage first = alice.send(bob, "1");
    REQUIRE(bob.receive(alice, first) == "1");
    const EncryptedMessage reply = bob.send(alice, "ok");
    REQUIRE(alice.receive(bob, reply) == "ok");

    const EncryptedMessage message = alice.send(bob, "pay 100");
    REQUIRE(bob.receive(alice, message) == "pay 100");

    // Атакующий отправляет то же сообщение ещё раз.
    try
    {
        bob.receive(alice, message);
        FAIL("replayed message must be rejected");
    }
    catch (const SignalException &error)
    {
        REQUIRE(error.code() == SG_ERR_DUPLICATE_MESSAGE);
    }
}

TEST_CASE("Tampered message is rejected", "[cipher][security]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);
    alice.startSessionWith(bob);

    const EncryptedMessage first = alice.send(bob, "1");
    REQUIRE(bob.receive(alice, first) == "1");
    const EncryptedMessage reply = bob.send(alice, "ok");
    REQUIRE(alice.receive(bob, reply) == "ok");

    EncryptedMessage tampered = alice.send(bob, "secret");
    // Портим байт в середине (внутри шифротекста), MAC в конце не сойдётся.
    tampered.body[tampered.body.size() / 2] ^= 0x01;
    REQUIRE_THROWS_AS(bob.receive(alice, tampered), SignalException);
}

TEST_CASE("Third party cannot decrypt", "[cipher][security]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);
    Party eve("eve", generator, 1);
    alice.startSessionWith(bob);

    const EncryptedMessage first = alice.send(bob, "for Bob only");
    // Ева перехватила сообщение (например, на сервере), но её ключей там нет.
    REQUIRE_THROWS_AS(eve.receive(alice, first), SignalException);
    // А Боб — читает.
    REQUIRE(bob.receive(alice, first) == "for Bob only");
}

TEST_CASE("MessageCipher rejects bad arguments", "[cipher][negative]")
{
    KeyGenerationService generator(appContext());
    Party alice("alice", generator, 1);
    Party bob("bob", generator, 1);

    // Без сессии шифровать нельзя.
    try
    {
        alice.send(bob, "too early");
        FAIL("encrypt without session must fail");
    }
    catch (const SignalException &error)
    {
        REQUIRE(error.code() == SG_ERR_NO_SESSION);
    }

    alice.startSessionWith(bob);
    REQUIRE_THROWS_AS(alice.cipher->encrypt("", 1, text("x")), CryptoException);

    EncryptedMessage unknownType;
    unknownType.type = 7;
    unknownType.body = text("whatever");
    REQUIRE_THROWS_AS(bob.cipher->decrypt("alice", 1, unknownType), CryptoException);

    EncryptedMessage empty;
    empty.type = MessageCipher::kSignalMessage;
    REQUIRE_THROWS_AS(bob.cipher->decrypt("alice", 1, empty), CryptoException);

    EncryptedMessage garbage;
    garbage.type = MessageCipher::kPreKeyMessage;
    garbage.body = text("definitely not protobuf");
    REQUIRE_THROWS_AS(bob.cipher->decrypt("alice", 1, garbage), SignalException);

    REQUIRE_THROWS_AS(MessageCipher(nullptr, *alice.stores), CryptoException);
}
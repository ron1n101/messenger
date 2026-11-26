#include "catch_amalgamated.hpp"
#include "core/session_establisher.h"
#include "core/protocol_store_context.h"
#include "core/signal_exception.h"
#include "core/key_generation_service.h"
#include "core/keybundle_adapter.h"
#include "core/store/in_memory_session_store.h"
#include "core/store/in_memory_identity_store.h"
#include "crypto/base64.h"
#include "crypto/signal_context_manager.h"
#include "crypto/crypto_exception.h"

#include <memory>
#include <string>

namespace {
    signal_context *appContext()
    {
        REQUIRE(SignalContextManager::instance().initialize());
        return SignalContextManager::instance().rawContext();
    }

    // Пакет Боба «как с сервера»: то, что Боб загрузил при регистрации (3.4),
    // превращённое обратно в ответ сервера.
    PreKeyBundlePayload bobBundlePayload(const GeneratedIdentity &bob, bool withOneTimeKey)
    {
        const RegisterKeysPayload uploaded = KeyBundleAdapter::toRegisterPayload(bob);
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

    // Всё, что нужно Алисе: её ключи, хранилища и контекст хранилищ.
    // Порядок полей важен: хранилища объявлены РАНЬШЕ контекста, поэтому
    // уничтожатся ПОЗЖЕ него (поля уничтожаются в обратном порядке).
    struct AliceSide
    {
        GeneratedIdentity identity;
        InMemorySessionStore sessions;
        std::unique_ptr<InMemoryIdentityStore> identities;
        std::unique_ptr<ProtocolStoreContext> stores;

        explicit AliceSide(KeyGenerationService &generator)
            : identity(generator.generateNewIdentity(1))
        {
            identities = std::make_unique<InMemoryIdentityStore>(identity.identityKeyPair.get(), identity.registrationId);
            stores = std::make_unique<ProtocolStoreContext>(appContext(), sessions, *identities);
        }
    };
}

TEST_CASE("Alice establishes a session from Bob's bundle", "[session]")
{
    KeyGenerationService generator(appContext());
    AliceSide alice(generator);
    const GeneratedIdentity bob = generator.generateNewIdentity(3);

    SignalPtr<session_pre_key_bundle> bundle =
        KeyBundleAdapter::toSessionPreKeyBundle(bobBundlePayload(bob, true), appContext());

    REQUIRE_FALSE(alice.stores->hasSession("bob", 1));

    SessionEstablisher establisher(appContext(), *alice.stores);
    REQUIRE_NOTHROW(establisher.establishSession("bob", 1, bundle.get()));

    // Сессия появилась и лежит в НАШЕМ хранилище сессий.
    REQUIRE(alice.stores->hasSession("bob", 1));
    REQUIRE(alice.sessions.size() == 1);
}

TEST_CASE("Session can be established without a one-time prekey", "[session]")
{
    KeyGenerationService generator(appContext());
    AliceSide alice(generator);
    const GeneratedIdentity bob = generator.generateNewIdentity(1);

    SignalPtr<session_pre_key_bundle> bundle =
        KeyBundleAdapter::toSessionPreKeyBundle(bobBundlePayload(bob, false), appContext());

    SessionEstablisher establisher(appContext(), *alice.stores);
    REQUIRE_NOTHROW(establisher.establishSession("bob", 1, bundle.get()));
    REQUIRE(alice.stores->hasSession("bob", 1));
}

TEST_CASE("Bundle with a forged signed prekey signature is rejected", "[session][security]")
{
    KeyGenerationService generator(appContext());
    AliceSide alice(generator);
    const GeneratedIdentity bob = generator.generateNewIdentity(1);

    // «Сервер» подменил подпись: меняем один бит.
    PreKeyBundlePayload forged = bobBundlePayload(bob, true);
    Bytes signature = CryptoUtils::base64Decode(forged.signedPreKey.signature);
    signature[0] ^= 0x01;
    forged.signedPreKey.signature = CryptoUtils::base64Encode(signature);

    SignalPtr<session_pre_key_bundle> bundle = KeyBundleAdapter::toSessionPreKeyBundle(forged, appContext());
    SessionEstablisher establisher(appContext(), *alice.stores);

    try
    {
        establisher.establishSession("bob", 1, bundle.get());
        FAIL("forged bundle must be rejected");
    }
    catch (const SignalException &error)
    {
        REQUIRE(error.code() == SG_ERR_INVALID_KEY);
    }

    // Никакой сессии не создано.
    REQUIRE_FALSE(alice.stores->hasSession("bob", 1));
    REQUIRE(alice.sessions.size() == 0);
}

TEST_CASE("Bundle with a substituted signed prekey is rejected", "[session][security]")
{
    // «Сервер» подсовывает СВОЙ signed prekey, но не может подписать его ключом Боба.
    KeyGenerationService generator(appContext());
    AliceSide alice(generator);
    const GeneratedIdentity bob = generator.generateNewIdentity(1);
    const GeneratedIdentity attacker = generator.generateNewIdentity(1);

    PreKeyBundlePayload substituted = bobBundlePayload(bob, false);
    substituted.signedPreKey = KeyBundleAdapter::toRegisterPayload(attacker).signedPreKey;

    SignalPtr<session_pre_key_bundle> bundle = KeyBundleAdapter::toSessionPreKeyBundle(substituted, appContext());
    SessionEstablisher establisher(appContext(), *alice.stores);

    REQUIRE_THROWS_AS(establisher.establishSession("bob", 1, bundle.get()), SignalException);
    REQUIRE_FALSE(alice.stores->hasSession("bob", 1));
}

TEST_CASE("Changed identity key of a known contact is not trusted", "[session][security]")
{
    KeyGenerationService generator(appContext());
    AliceSide alice(generator);
    const GeneratedIdentity bob = generator.generateNewIdentity(1);
    const GeneratedIdentity impostor = generator.generateNewIdentity(1);

    SessionEstablisher establisher(appContext(), *alice.stores);

    // Первая встреча с Бобом: доверяем (TOFU), ключ Боба запомнен.
    SignalPtr<session_pre_key_bundle> realBundle =
        KeyBundleAdapter::toSessionPreKeyBundle(bobBundlePayload(bob, false), appContext());
    establisher.establishSession("bob", 1, realBundle.get());

    // Позже под именем "bob" приходит пакет с ДРУГИМ ключом личности.
    SignalPtr<session_pre_key_bundle> impostorBundle =
        KeyBundleAdapter::toSessionPreKeyBundle(bobBundlePayload(impostor, false), appContext());

    try
    {
        establisher.establishSession("bob", 1, impostorBundle.get());
        FAIL("changed identity key must not be trusted");
    }
    catch (const SignalException &error)
    {
        REQUIRE(error.code() == SG_ERR_UNTRUSTED_IDENTITY);
    }
}

TEST_CASE("SessionEstablisher rejects bad arguments", "[session][negative]")
{
    KeyGenerationService generator(appContext());
    AliceSide alice(generator);
    SessionEstablisher establisher(appContext(), *alice.stores);

    REQUIRE_THROWS_AS(establisher.establishSession("bob", 1, nullptr), CryptoException);

    const GeneratedIdentity bob = generator.generateNewIdentity(1);
    SignalPtr<session_pre_key_bundle> bundle =
        KeyBundleAdapter::toSessionPreKeyBundle(bobBundlePayload(bob, false), appContext());
    REQUIRE_THROWS_AS(establisher.establishSession("", 1, bundle.get()), CryptoException);

    REQUIRE_THROWS_AS(SessionEstablisher(nullptr, *alice.stores), CryptoException);
    REQUIRE_THROWS_AS(ProtocolStoreContext(nullptr, alice.sessions, *alice.identities), CryptoException);
}
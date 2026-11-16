#include "catch_amalgamated.hpp"
#include "core/store/in_memory_session_store.h"
#include "core/store/in_memory_identity_store.h"
#include "core/key_generation_service.h"
#include "crypto/signal_context_manager.h"
#include "crypto/crypto_exception.h"
#include "crypto/types.h"

#include "curve.h"

#include <cstring>
#include <memory>

// Эти тесты вызывают коллбэки ТОЧНО ТАК ЖЕ, как их будет вызывать libsignal:
// через указатели из структуры (store.load_session_func(...)) и с store.user_data
// последним параметром.

namespace {
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;
    using SecretBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_bzero_free)>;
    using IntListPtr = std::unique_ptr<signal_int_list, decltype(&signal_int_list_free)>;

    signal_context *appContext()
    {
        REQUIRE(SignalContextManager::instance().initialize());
        return SignalContextManager::instance().rawContext();
    }

    // Адрес собеседника. Имя — строковый литерал ("bob"): он живёт всю программу,
    // поэтому указатель address.name не «повиснет» (см. теорию 1.5 в брифинге).
    signal_protocol_address makeAddress(const char *name, int deviceId)
    {
        signal_protocol_address address{};
        address.name = name;
        address.name_len = std::strlen(name);
        address.device_id = deviceId;
        return address;
    }

    Bytes bufferToBytes(const signal_buffer *buffer)
    {
        const uint8_t *begin = signal_buffer_const_data(buffer);
        return Bytes(begin, begin + signal_buffer_len(buffer));
    }

    Bytes serializedPublicKey(const ratchet_identity_key_pair *identity)
    {
        signal_buffer *raw = nullptr;
        REQUIRE(ec_public_key_serialize(&raw, ratchet_identity_key_pair_get_public(identity)) == SG_SUCCESS);
        SignalBufferPtr buffer(raw, signal_buffer_free);
        return bufferToBytes(buffer.get());
    }
}

// =====================================================================
// 1. Хранилище сессий
// =====================================================================
TEST_CASE("Session store struct points back to the store object", "[store][session]")
{
    InMemorySessionStore sessions;
    const signal_protocol_session_store store = sessions.toSignalStore();

    REQUIRE(store.user_data == &sessions);
    REQUIRE(store.load_session_func != nullptr);
    REQUIRE(store.get_sub_device_sessions_func != nullptr);
    REQUIRE(store.store_session_func != nullptr);
    REQUIRE(store.contains_session_func != nullptr);
    REQUIRE(store.delete_session_func != nullptr);
    REQUIRE(store.delete_all_sessions_func != nullptr);
    // Объект хранилища — наш (C++), библиотека не должна его уничтожать.
    REQUIRE(store.destroy_func == nullptr);
}

TEST_CASE("Session store: empty store has no sessions", "[store][session]")
{
    InMemorySessionStore sessions;
    signal_protocol_session_store store = sessions.toSignalStore();
    const signal_protocol_address bob = makeAddress("bob", 1);

    // Контракт load: 0 = «не найдено», и record остаётся пустым.
    signal_buffer *record = nullptr;
    REQUIRE(store.load_session_func(&record, nullptr, &bob, store.user_data) == 0);
    REQUIRE(record == nullptr);

    REQUIRE(store.contains_session_func(&bob, store.user_data) == 0);
    REQUIRE(sessions.size() == 0);
}

TEST_CASE("Session store: store then load returns the same bytes", "[store][session]")
{
    InMemorySessionStore sessions;
    signal_protocol_session_store store = sessions.toSignalStore();
    const signal_protocol_address bob = makeAddress("bob", 1);

    Bytes record = {0x01, 0x02, 0x03, 0x04, 0xFF};
    REQUIRE(store.store_session_func(&bob, record.data(), record.size(), nullptr, 0, store.user_data) == 0);
    REQUIRE(store.contains_session_func(&bob, store.user_data) == 1);

    // Контракт load: 1 = «загружено», record — НОВЫЙ буфер, освобождает тот, кто вызвал.
    signal_buffer *rawLoaded = nullptr;
    signal_buffer *rawUserRecord = nullptr;
    REQUIRE(store.load_session_func(&rawLoaded, &rawUserRecord, &bob, store.user_data) == 1);
    SignalBufferPtr loaded(rawLoaded, signal_buffer_free);
    REQUIRE(bufferToBytes(loaded.get()) == record);
    // Дополнительных данных приложения мы не храним.
    REQUIRE(rawUserRecord == nullptr);

    // Повторное сохранение заменяет запись, а не добавляет вторую.
    Bytes newer = {0x09, 0x08};
    REQUIRE(store.store_session_func(&bob, newer.data(), newer.size(), nullptr, 0, store.user_data) == 0);
    REQUIRE(sessions.size() == 1);

    rawLoaded = nullptr;
    REQUIRE(store.load_session_func(&rawLoaded, nullptr, &bob, store.user_data) == 1);
    SignalBufferPtr loadedNewer(rawLoaded, signal_buffer_free);
    REQUIRE(bufferToBytes(loadedNewer.get()) == newer);
}

TEST_CASE("Session store: addresses differ by name and by device", "[store][session]")
{
    InMemorySessionStore sessions;
    signal_protocol_session_store store = sessions.toSignalStore();
    const signal_protocol_address bobPhone = makeAddress("bob", 1);
    const signal_protocol_address bobLaptop = makeAddress("bob", 2);
    const signal_protocol_address carol = makeAddress("carol", 1);

    Bytes record = {0xAA};
    REQUIRE(store.store_session_func(&bobPhone, record.data(), record.size(), nullptr, 0, store.user_data) == 0);

    // Тот же Боб, но другое устройство — другая сессия. И другое имя — тоже.
    REQUIRE(store.contains_session_func(&bobLaptop, store.user_data) == 0);
    REQUIRE(store.contains_session_func(&carol, store.user_data) == 0);
}

TEST_CASE("Session store: sub-device sessions exclude the main device", "[store][session]")
{
    InMemorySessionStore sessions;
    signal_protocol_session_store store = sessions.toSignalStore();
    const signal_protocol_address bob1 = makeAddress("bob", 1);
    const signal_protocol_address bob2 = makeAddress("bob", 2);
    const signal_protocol_address bob3 = makeAddress("bob", 3);
    const signal_protocol_address carol2 = makeAddress("carol", 2);

    Bytes record = {0x01};
    for (const signal_protocol_address *address : {&bob1, &bob2, &bob3, &carol2})
    {
        REQUIRE(store.store_session_func(address, record.data(), record.size(), nullptr, 0, store.user_data) == 0);
    }

    // У Боба дополнительные устройства — 2 и 3 (устройство 1 — основное, его нет в списке).
    signal_int_list *rawList = nullptr;
    REQUIRE(store.get_sub_device_sessions_func(&rawList, "bob", 3, store.user_data) == 2);
    IntListPtr list(rawList, signal_int_list_free);
    REQUIRE(signal_int_list_size(list.get()) == 2);
    REQUIRE(signal_int_list_at(list.get(), 0) == 2);
    REQUIRE(signal_int_list_at(list.get(), 1) == 3);
}

TEST_CASE("Session store: delete one and delete all", "[store][session]")
{
    InMemorySessionStore sessions;
    signal_protocol_session_store store = sessions.toSignalStore();
    const signal_protocol_address bob1 = makeAddress("bob", 1);
    const signal_protocol_address bob2 = makeAddress("bob", 2);
    const signal_protocol_address carol = makeAddress("carol", 1);

    Bytes record = {0x01};
    for (const signal_protocol_address *address : {&bob1, &bob2, &carol})
    {
        REQUIRE(store.store_session_func(address, record.data(), record.size(), nullptr, 0, store.user_data) == 0);
    }

    // Контракт delete: 1 = удалили, 0 = нечего было удалять.
    REQUIRE(store.delete_session_func(&bob1, store.user_data) == 1);
    REQUIRE(store.delete_session_func(&bob1, store.user_data) == 0);
    REQUIRE(store.contains_session_func(&bob1, store.user_data) == 0);

    // delete_all удаляет все устройства Боба и возвращает, сколько удалено. Кэрол остаётся.
    REQUIRE(store.delete_all_sessions_func("bob", 3, store.user_data) == 1);
    REQUIRE(store.contains_session_func(&bob2, store.user_data) == 0);
    REQUIRE(store.contains_session_func(&carol, store.user_data) == 1);
    REQUIRE(sessions.size() == 1);
}

// =====================================================================
// 2. Хранилище ключей личности
// =====================================================================
TEST_CASE("Identity store returns our own key pair and registration id", "[store][identity]")
{
    KeyGenerationService generator(appContext());
    SignalPtr<ratchet_identity_key_pair> me = generator.generateIdentityKeyPair();

    InMemoryIdentityStore identities(me.get(), 777);
    signal_protocol_identity_key_store store = identities.toSignalStore();
    REQUIRE(store.user_data == &identities);
    REQUIRE(store.destroy_func == nullptr);

    uint32_t registrationId = 0;
    REQUIRE(store.get_local_registration_id(store.user_data, &registrationId) == 0);
    REQUIRE(registrationId == 777);

    // Буферы создаёт хранилище, освобождает вызывающий. В private_data секрет — затираем.
    signal_buffer *rawPublic = nullptr;
    signal_buffer *rawPrivate = nullptr;
    REQUIRE(store.get_identity_key_pair(&rawPublic, &rawPrivate, store.user_data) == 0);
    SignalBufferPtr publicKey(rawPublic, signal_buffer_free);
    SecretBufferPtr privateKey(rawPrivate, signal_buffer_bzero_free);

    REQUIRE(bufferToBytes(publicKey.get()) == serializedPublicKey(me.get()));
    REQUIRE(signal_buffer_len(privateKey.get()) == 32);

    // Приватный ключ из хранилища — это действительно наш приватный ключ.
    ec_private_key *rawRestored = nullptr;
    REQUIRE(curve_decode_private_point(&rawRestored, signal_buffer_data(privateKey.get()),
                                       signal_buffer_len(privateKey.get()), appContext()) == SG_SUCCESS);
    SignalPtr<ec_private_key> restored(rawRestored);
    REQUIRE(ec_private_key_compare(restored.get(), ratchet_identity_key_pair_get_private(me.get())) == 0);
}

TEST_CASE("Identity store trusts on first use and detects key change", "[store][identity]")
{
    KeyGenerationService generator(appContext());
    SignalPtr<ratchet_identity_key_pair> me = generator.generateIdentityKeyPair();
    SignalPtr<ratchet_identity_key_pair> realBob = generator.generateIdentityKeyPair();
    SignalPtr<ratchet_identity_key_pair> fakeBob = generator.generateIdentityKeyPair();

    InMemoryIdentityStore identities(me.get(), 1);
    signal_protocol_identity_key_store store = identities.toSignalStore();
    const signal_protocol_address bob = makeAddress("bob", 1);

    Bytes realKey = serializedPublicKey(realBob.get());
    Bytes fakeKey = serializedPublicKey(fakeBob.get());

    // Первая встреча: про Боба ничего не знаем — доверяем (TOFU).
    REQUIRE(store.is_trusted_identity(&bob, realKey.data(), realKey.size(), store.user_data) == 1);

    // Запомнили ключ Боба.
    REQUIRE(store.save_identity(&bob, realKey.data(), realKey.size(), store.user_data) == 0);

    // Тот же ключ — по-прежнему доверяем. Другой ключ — НЕ доверяем: это может быть подмена.
    REQUIRE(store.is_trusted_identity(&bob, realKey.data(), realKey.size(), store.user_data) == 1);
    REQUIRE(store.is_trusted_identity(&bob, fakeKey.data(), fakeKey.size(), store.user_data) == 0);

    // Доверие привязано к адресу: для Кэрол этот ключ ещё «первая встреча».
    const signal_protocol_address carol = makeAddress("carol", 1);
    REQUIRE(store.is_trusted_identity(&carol, fakeKey.data(), fakeKey.size(), store.user_data) == 1);
}

TEST_CASE("Identity store forgets a contact when key_data is null", "[store][identity]")
{
    KeyGenerationService generator(appContext());
    SignalPtr<ratchet_identity_key_pair> me = generator.generateIdentityKeyPair();
    SignalPtr<ratchet_identity_key_pair> oldBob = generator.generateIdentityKeyPair();
    SignalPtr<ratchet_identity_key_pair> newBob = generator.generateIdentityKeyPair();

    InMemoryIdentityStore identities(me.get(), 1);
    signal_protocol_identity_key_store store = identities.toSignalStore();
    const signal_protocol_address bob = makeAddress("bob", 1);

    Bytes oldKey = serializedPublicKey(oldBob.get());
    Bytes newKey = serializedPublicKey(newBob.get());

    REQUIRE(store.save_identity(&bob, oldKey.data(), oldKey.size(), store.user_data) == 0);
    REQUIRE(store.is_trusted_identity(&bob, newKey.data(), newKey.size(), store.user_data) == 0);

    // По контракту key_data == nullptr значит «забыть ключ этого собеседника»
    // (так будет работать кнопка «я сверил Safety Number, доверять новому ключу»).
    REQUIRE(store.save_identity(&bob, nullptr, 0, store.user_data) == 0);
    REQUIRE(store.is_trusted_identity(&bob, newKey.data(), newKey.size(), store.user_data) == 1);
}

TEST_CASE("Identity store rejects a null identity", "[store][identity][negative]")
{
    REQUIRE_THROWS_AS(InMemoryIdentityStore(nullptr, 1), CryptoException);
}
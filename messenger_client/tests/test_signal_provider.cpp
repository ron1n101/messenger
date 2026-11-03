#include "catch_amalgamated.hpp"
#include "crypto/signal_bridge.h"
#include "crypto/helper.h"   // bytesFromHex
#include "crypto/types.h"

// Публичные заголовки libsignal. В них есть extern "C", поэтому их можно
// подключать из C++ напрямую (см. теорию 1.7 в брифинге 2.9.5).
#include "curve.h"           // ключи Curve25519
#include "fingerprint.h"     // Safety Number
#include "hkdf.h"            // HKDF самой библиотеки

#include <cstdlib>           // std::free
#include <cstring>           // std::memcmp
#include <memory>
#include <string>

namespace {
    // -----------------------------------------------------------------
    // RAII-обёртки для объектов libsignal.
    // Объект освободится сам, даже если какой-то REQUIRE упадёт посреди теста.
    // -----------------------------------------------------------------

    // signal_context освобождается функцией signal_context_destroy.
    using SignalContextPtr = std::unique_ptr<signal_context, decltype(&signal_context_destroy)>;

    // Объекты с подсчётом ссылок (ключи, fingerprint, hkdf_context).
    // Макрос SIGNAL_UNREF внутри вызывает функцию signal_type_unref —
    // её и используем в deleter (макрос в deleter передать нельзя).
    struct SignalUnref
    {
        void operator()(void *object) const
        {
            signal_type_unref(static_cast<signal_type_base *>(object));
        }
    };
    using EcPublicKeyPtr  = std::unique_ptr<ec_public_key, SignalUnref>;
    using EcKeyPairPtr    = std::unique_ptr<ec_key_pair, SignalUnref>;
    using FingerprintPtr  = std::unique_ptr<fingerprint, SignalUnref>;
    using HkdfContextPtr  = std::unique_ptr<hkdf_context, SignalUnref>;

    // У генератора Safety Number своя функция освобождения.
    using FingerprintGeneratorPtr =
        std::unique_ptr<fingerprint_generator, decltype(&fingerprint_generator_free)>;

    // Память, которую библиотека выделила через malloc, освобождаем через free.
    struct CFree
    {
        void operator()(uint8_t *memory) const { std::free(memory); }
    };
    using CBytesPtr = std::unique_ptr<uint8_t, CFree>;

    // Создаёт контекст и регистрирует в нём наш провайдер.
    SignalContextPtr makeContextWithProvider()
    {
        signal_context *raw = nullptr;
        REQUIRE(signal_context_create(&raw, nullptr) == SG_SUCCESS);
        SignalContextPtr context(raw, signal_context_destroy);

        // provider — локальная переменная. Это нормально:
        // signal_context_set_crypto_provider копирует структуру к себе (memcpy).
        signal_crypto_provider provider = SignalBridge::makeCryptoProvider();
        REQUIRE(signal_context_set_crypto_provider(context.get(), &provider) == SG_SUCCESS);

        return context;
    }
}

// =====================================================================
// 1. Структура заполнена полностью
// =====================================================================
TEST_CASE("makeCryptoProvider fills every callback", "[provider]")
{
    const signal_crypto_provider provider = SignalBridge::makeCryptoProvider();

    // Проверяем все 11 полей: сама библиотека проверяет только 4 HMAC-поля,
    // а забытое поле SHA-512 или AES упало бы намного позже.
    REQUIRE(provider.random_func != nullptr);

    REQUIRE(provider.hmac_sha256_init_func != nullptr);
    REQUIRE(provider.hmac_sha256_update_func != nullptr);
    REQUIRE(provider.hmac_sha256_final_func != nullptr);
    REQUIRE(provider.hmac_sha256_cleanup_func != nullptr);

    REQUIRE(provider.sha512_digest_init_func != nullptr);
    REQUIRE(provider.sha512_digest_update_func != nullptr);
    REQUIRE(provider.sha512_digest_final_func != nullptr);
    REQUIRE(provider.sha512_digest_cleanup_func != nullptr);

    REQUIRE(provider.encrypt_func != nullptr);
    REQUIRE(provider.decrypt_func != nullptr);

    // «Записка для себя» нам не нужна.
    REQUIRE(provider.user_data == nullptr);
}

// =====================================================================
// 2. Библиотека принимает наш провайдер и отвергает неполный
// =====================================================================
TEST_CASE("signal_context accepts our provider and rejects an incomplete one", "[provider]")
{
    // Полный провайдер принимается (REQUIRE внутри makeContextWithProvider).
    SignalContextPtr context = makeContextWithProvider();
    REQUIRE(context != nullptr);

    // Провайдер без HMAC-init библиотека должна отвергнуть.
    signal_crypto_provider broken = SignalBridge::makeCryptoProvider();
    broken.hmac_sha256_init_func = nullptr;
    REQUIRE(signal_context_set_crypto_provider(context.get(), &broken) == SG_ERR_INVAL);
}

// =====================================================================
// 3. HKDF библиотеки, работающий на нашем HMAC, = RFC 5869 Test Case 1
// =====================================================================
TEST_CASE("libsignal HKDF over our HMAC matches RFC 5869 TC1", "[provider][integration]")
{
    SignalContextPtr context = makeContextWithProvider();

    // Тот же вектор, что в test_kdf.cpp (задача 2.4).
    const Bytes ikm(22, 0x0b);
    const Bytes salt = bytesFromHex("000102030405060708090a0b0c");
    const Bytes info = bytesFromHex("f0f1f2f3f4f5f6f7f8f9");
    const Bytes expectedOkm = bytesFromHex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    // Версия 3 — текущая версия протокола.
    hkdf_context *rawHkdf = nullptr;
    REQUIRE(hkdf_create(&rawHkdf, 3, context.get()) == SG_SUCCESS);
    HkdfContextPtr hkdf(rawHkdf);

    // Библиотека сама выделит буфер через malloc и вернёт его длину.
    uint8_t *rawOutput = nullptr;
    const ssize_t length = hkdf_derive_secrets(hkdf.get(), &rawOutput,
                                               ikm.data(), ikm.size(),
                                               salt.data(), salt.size(),
                                               info.data(), info.size(),
                                               42);
    CBytesPtr output(rawOutput);

    REQUIRE(length == 42);
    REQUIRE(Bytes(output.get(), output.get() + length) == expectedOkm);
}

// =====================================================================
// 4. Safety Number библиотеки, работающий на нашем SHA-512, = эталон
// =====================================================================
TEST_CASE("libsignal fingerprint over our SHA-512 matches reference vector", "[provider][integration]")
{
    SignalContextPtr context = makeContextWithProvider();

    // Ключи из tests/test_fingerprint.c самой libsignal.
    // 33 байта: 0x05 — тип ключа (Curve25519), затем 32 байта ключа.
    const Bytes aliceKeyBytes = bytesFromHex(
        "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868");
    const Bytes bobKeyBytes = bytesFromHex(
        "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b");
    const std::string expected = "300354477692869396892869876765458257569162576843440918079131";

    // Байты -> объекты ключей библиотеки.
    ec_public_key *rawAliceKey = nullptr;
    REQUIRE(curve_decode_point(&rawAliceKey, aliceKeyBytes.data(), aliceKeyBytes.size(),
                               context.get()) == SG_SUCCESS);
    EcPublicKeyPtr aliceKey(rawAliceKey);

    ec_public_key *rawBobKey = nullptr;
    REQUIRE(curve_decode_point(&rawBobKey, bobKeyBytes.data(), bobKeyBytes.size(),
                               context.get()) == SG_SUCCESS);
    EcPublicKeyPtr bobKey(rawBobKey);

    // 5200 итераций SHA-512 (как в Signal), версия формата 0.
    fingerprint_generator *rawGenerator = nullptr;
    REQUIRE(fingerprint_generator_create(&rawGenerator, 5200, 0, context.get()) == SG_SUCCESS);
    FingerprintGeneratorPtr generator(rawGenerator, fingerprint_generator_free);

    // Safety Number «глазами Алисы»: её номер и ключ, номер и ключ Боба.
    fingerprint *rawAliceFingerprint = nullptr;
    REQUIRE(fingerprint_generator_create_for(generator.get(),
                                             "+14152222222", aliceKey.get(),
                                             "+14153333333", bobKey.get(),
                                             &rawAliceFingerprint) == SG_SUCCESS);
    FingerprintPtr aliceFingerprint(rawAliceFingerprint);

    // «Глазами Боба» — номера и ключи меняются местами, а 60 цифр должны совпасть.
    fingerprint *rawBobFingerprint = nullptr;
    REQUIRE(fingerprint_generator_create_for(generator.get(),
                                             "+14153333333", bobKey.get(),
                                             "+14152222222", aliceKey.get(),
                                             &rawBobFingerprint) == SG_SUCCESS);
    FingerprintPtr bobFingerprint(rawBobFingerprint);

    // displayable — часть самого fingerprint, отдельно её освобождать не нужно.
    const std::string aliceText =
        displayable_fingerprint_text(fingerprint_get_displayable(aliceFingerprint.get()));
    const std::string bobText =
        displayable_fingerprint_text(fingerprint_get_displayable(bobFingerprint.get()));

    REQUIRE(aliceText == expected);
    REQUIRE(bobText == expected);
}

// =====================================================================
// 5. Генерация ключей библиотекой на нашем random + общий секрет
// =====================================================================
TEST_CASE("libsignal key generation uses our random and agreement works", "[provider][integration]")
{
    SignalContextPtr context = makeContextWithProvider();

    // curve_generate_key_pair внутри вызывает наш randomFunc для приватного ключа.
    ec_key_pair *rawAlice = nullptr;
    REQUIRE(curve_generate_key_pair(context.get(), &rawAlice) == SG_SUCCESS);
    EcKeyPairPtr alice(rawAlice);

    ec_key_pair *rawBob = nullptr;
    REQUIRE(curve_generate_key_pair(context.get(), &rawBob) == SG_SUCCESS);
    EcKeyPairPtr bob(rawBob);

    // Два случайных ключа совпасть не могут (compare возвращает 0, если равны).
    REQUIRE(ec_public_key_compare(ec_key_pair_get_public(alice.get()),
                                  ec_key_pair_get_public(bob.get())) != 0);

    // Diffie-Hellman (как в задаче 2.2): секрет Алисы с публичным ключом Боба
    // должен совпасть с секретом Боба с публичным ключом Алисы.
    uint8_t *rawAliceShared = nullptr;
    const int aliceLength = curve_calculate_agreement(&rawAliceShared,
                                                      ec_key_pair_get_public(bob.get()),
                                                      ec_key_pair_get_private(alice.get()));
    CBytesPtr aliceShared(rawAliceShared);

    uint8_t *rawBobShared = nullptr;
    const int bobLength = curve_calculate_agreement(&rawBobShared,
                                                    ec_key_pair_get_public(alice.get()),
                                                    ec_key_pair_get_private(bob.get()));
    CBytesPtr bobShared(rawBobShared);

    REQUIRE(aliceLength == 32);
    REQUIRE(bobLength == 32);
    REQUIRE(std::memcmp(aliceShared.get(), bobShared.get(), 32) == 0);
}
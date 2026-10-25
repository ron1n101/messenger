#include "catch_amalgamated.hpp"
#include "crypto/sha512.h"
#include "crypto/signal_bridge.h"
#include "crypto/helper.h"   // bytesFromHex
#include <memory>
#include <string>

namespace {
    Bytes bytesFromString(const std::string &text) { return Bytes(text.begin(), text.end()); }

    // FIPS 180-2: SHA-512("abc")
    const Bytes kAbcHash = bytesFromHex(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    // По образцу твоих тестов из 2.9.2/2.9.3: освобождает буфер даже при упавшем REQUIRE.
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;

    struct Sha512ContextDeleter
    {
        void operator()(void *context) const
        {
            SignalBridge::sha512CleanupFunc(context, nullptr);
        }
    };

    using Sha512ContextPtr = std::unique_ptr<void, Sha512ContextDeleter>;

    Bytes bytesFromSignalBuffer(signal_buffer *buffer)
    {
        const uint8_t *begin = signal_buffer_data(buffer);
        return Bytes(begin, begin + signal_buffer_len(buffer));
    }
}

// =====================================================================
// Часть A: sha512 и класс Sha512
// =====================================================================

TEST_CASE("SHA-512 matches FIPS 180-2 vectors", "[sha512]")
{
    REQUIRE(CryptoUtils::sha512(bytesFromString("abc")) == kAbcHash);

    // Пустой вход.
    const Bytes emptyHash = bytesFromHex(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    REQUIRE(CryptoUtils::sha512(Bytes{}) == emptyHash);

    // 112 байт — переход через границу блока.
    const Bytes twoBlockInput = bytesFromString(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
    const Bytes twoBlockHash = bytesFromHex(
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    REQUIRE(twoBlockInput.size() == 112);
    REQUIRE(CryptoUtils::sha512(twoBlockInput) == twoBlockHash);
}

TEST_CASE("Sha512 in pieces equals one-shot", "[sha512]")
{
    const Bytes ab = bytesFromString("ab");
    const Bytes c = bytesFromString("c");

    CryptoUtils::Sha512 hasher;
    hasher.update(ab.data(), ab.size());
    hasher.update(nullptr, 0);
    hasher.update(c.data(), c.size());
    REQUIRE(hasher.final() == kAbcHash);
}

// ГЛАВНЫЙ тест задачи: повторное использование после final.
TEST_CASE("Sha512 can be reused after final", "[sha512]")
{
    const Bytes abc = bytesFromString("abc");
    CryptoUtils::Sha512 hasher;

    // Три круга подряд на ОДНОМ объекте — как в цикле fingerprint.c.
    for (int round = 0; round < 3; ++round)
    {
        hasher.update(abc.data(), abc.size());
        REQUIRE(hasher.final() == kAbcHash);
    }
    // Если забыть restart() в final(), второй круг даст другой результат и тест упадёт.
}

// =====================================================================
// Часть B: коллбэки моста
// =====================================================================

TEST_CASE("Bridge SHA-512 callbacks work and reuse the context", "[sha512][bridge]")
{
    void *context = nullptr;
    REQUIRE(SignalBridge::sha512InitFunc(&context, nullptr) == SG_SUCCESS);
    REQUIRE(context != nullptr);
    Sha512ContextPtr contextGuard(context);

    const Bytes abc = bytesFromString("abc");

    // Два круга на одном контексте — как это делает libsignal.
    for (int round = 0; round < 2; ++round)
    {
        REQUIRE(SignalBridge::sha512UpdateFunc(contextGuard.get(), abc.data(), abc.size(), nullptr) == SG_SUCCESS);

        signal_buffer *rawOutput = nullptr;
        REQUIRE(SignalBridge::sha512FinalFunc(contextGuard.get(), &rawOutput, nullptr) == SG_SUCCESS);
        SignalBufferPtr output(rawOutput, signal_buffer_free);

        REQUIRE(output != nullptr);
        REQUIRE(bytesFromSignalBuffer(output.get()) == kAbcHash);
    }
}

TEST_CASE("Bridge SHA-512 callbacks handle bad arguments", "[sha512][bridge][negative]")
{
    // По образцу твоего теста "Bridge HMAC callbacks handle bad arguments".
    REQUIRE_NOTHROW(SignalBridge::sha512CleanupFunc(nullptr, nullptr));
    REQUIRE(SignalBridge::sha512InitFunc(nullptr, nullptr) == SG_ERR_INVAL);

    const Bytes data = bytesFromString("x");
    REQUIRE(SignalBridge::sha512UpdateFunc(nullptr, data.data(), data.size(), nullptr) == SG_ERR_INVAL);

    signal_buffer *output = nullptr;
    REQUIRE(SignalBridge::sha512FinalFunc(nullptr, &output, nullptr) == SG_ERR_INVAL);
    REQUIRE(output == nullptr);
}
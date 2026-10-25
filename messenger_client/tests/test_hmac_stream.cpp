#include "catch_amalgamated.hpp"
#include "crypto/hmac.h"
#include "crypto/signal_bridge.h"
#include "crypto/crypto_exception.h"
#include "crypto/helper.h"
#include <string>
#include <memory>

namespace {
    Bytes bytesFromString(const std::string &text)
    {
        return Bytes(text.begin(), text.end());
    }

    struct HmacContextDeleter
    {
        void operator()(void *context) const
        {
            SignalBridge::hmacCleanupFunc(context, nullptr);
        }
    };

    using HmacContextPtr = std::unique_ptr<void, HmacContextDeleter>;
    using SignalBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_free)>;

    Bytes bytesFromSignalBuffer(signal_buffer *buffer)
    {
        const size_t length = signal_buffer_len(buffer);
        if (length == 0)
        {
            return {};
        }

        const uint8_t *begin = signal_buffer_data(buffer);
        return Bytes(begin, begin + length);
    }
}

TEST_CASE("HmacSha256 in pieces equals RFC 4231 TC2", "[hmac_stream]")
{
    const Bytes key = bytesFromString("Jefe");
    const Bytes first = bytesFromString("what do ya");
    const Bytes second = bytesFromString(" want for nothing?");
    const Bytes expected = bytesFromHex(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    CryptoUtils::HmacSha256 hmac(key);
    hmac.update(first.data(), first.size());
    // A null pointer is valid when the chunk length is zero; it adds no data.
    hmac.update(nullptr, 0);
    hmac.update(second.data(), second.size());

    REQUIRE(hmac.final() == expected);
}

TEST_CASE("HmacSha256 cannot be used after final", "[hmac_stream][negative]")
{
    const Bytes key = bytesFromString("key");
    const Bytes data = bytesFromString("data");

    CryptoUtils::HmacSha256 hmac(key);
    hmac.update(data.data(), data.size());
    hmac.final();

    // final() closes the stream, so neither another final() nor update() is valid.
    REQUIRE_THROWS_AS(hmac.final(), CryptoException);
    REQUIRE_THROWS_AS(hmac.update(data.data(), data.size()), CryptoException);
}

TEST_CASE("HmacSha256 with empty key and no data matches one-shot", "[hmac_stream][edge]")
{
    CryptoUtils::HmacSha256 hmac(Bytes{});
    // Both APIs must handle the same edge case: an empty key and empty message.
    REQUIRE(hmac.final() == CryptoUtils::hmacSha256(Bytes{}, Bytes{}));
}

TEST_CASE("Bridge HMAC callbacks match RFC 4231 TC1", "[hmac_stream][bridge]")
{
    const Bytes key(20, 0x0b);
    const Bytes data = bytesFromString("Hi There");
    const Bytes expected = bytesFromHex(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    // init creates the streaming HMAC state that update() and final() use.
    void *rawContext = nullptr;
    REQUIRE(SignalBridge::hmacInitFunc(&rawContext, key.data(), key.size(), nullptr) == SG_SUCCESS);
    REQUIRE(rawContext != nullptr);
    HmacContextPtr context(rawContext);

    // Feed "Hi There" in two chunks to verify that callback updates accumulate.
    REQUIRE(SignalBridge::hmacUpdateFunc(context.get(), data.data(), 3, nullptr) == SG_SUCCESS);
    REQUIRE(SignalBridge::hmacUpdateFunc(context.get(), data.data() + 3,
                                         data.size() - 3, nullptr) == SG_SUCCESS);

    signal_buffer *rawOutput = nullptr;
    REQUIRE(SignalBridge::hmacFinalFunc(context.get(), &rawOutput, nullptr) == SG_SUCCESS);
    SignalBufferPtr output(rawOutput, signal_buffer_free);
    REQUIRE(output != nullptr);

    REQUIRE(bytesFromSignalBuffer(output.get()) == expected);
}

TEST_CASE("Bridge HMAC callbacks handle bad arguments", "[hmac_stream][bridge][negative]")
{
    // libsignal may call cleanup even when init failed; deleting nullptr is safe.
    REQUIRE_NOTHROW(SignalBridge::hmacCleanupFunc(nullptr, nullptr));

    REQUIRE(SignalBridge::hmacInitFunc(nullptr, nullptr, 0, nullptr) == SG_ERR_INVAL);

    // A non-empty key cannot come from a null pointer. init must clear the output
    // context before returning an error, even if it initially contains garbage.
    void *context = reinterpret_cast<void *>(1);
    REQUIRE(SignalBridge::hmacInitFunc(&context, nullptr, 5, nullptr) == SG_ERR_INVAL);
    REQUIRE(context == nullptr);

    const Bytes data = bytesFromString("x");
    signal_buffer *output = nullptr;
    REQUIRE(SignalBridge::hmacUpdateFunc(nullptr, data.data(), data.size(), nullptr) == SG_ERR_INVAL);
    REQUIRE(SignalBridge::hmacFinalFunc(nullptr, &output, nullptr) == SG_ERR_INVAL);
    REQUIRE(SignalBridge::hmacFinalFunc(nullptr, nullptr, nullptr) == SG_ERR_INVAL);
    REQUIRE(output == nullptr);
}
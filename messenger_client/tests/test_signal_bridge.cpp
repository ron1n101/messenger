#include "catch_amalgamated.hpp"
#include "crypto/signal_bridge.h"
#include "crypto/helper.h"
#include "crypto/types.h"
#include <cstring>
#include <memory>

namespace {
    // Releases each signal_buffer automatically, even if a REQUIRE fails.
    using SignalBufferPtr = std::unique_ptr<signal_buffer, void (*)(signal_buffer *)>;

    // Copies a libsignal buffer into Bytes so tests can compare its contents.
    Bytes toBytes(signal_buffer *buffer)
    {
        const size_t length = signal_buffer_len(buffer);
        if (length == 0)
        {
            return {};
        }

        const uint8_t *begin = signal_buffer_data(buffer);
        return Bytes(begin, begin + length);
    }

    // AES-256-CBC key and IV from a NIST test vector.
    const Bytes kKey = bytesFromHex("603deb1015ca71be2b73aef0857d7781"
                                    "1f352c073b6108d72d9810a30914dff4");
    const Bytes kIv = bytesFromHex("000102030405060708090a0b0c0d0e0f");

    // One plaintext block. CBC adds a separate block for padding.
    const Bytes kPlain = bytesFromHex("6bc1bee22e409f96e93d7e117393172a");
    const Bytes kCipher = bytesFromHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                                       "485a5c81519cf378fa36d42b8547edc0");
}

TEST_CASE("randomFunc fills requested buffers with random bytes", "[bridge]")
{
    uint8_t first[32] = {0};
    uint8_t second[32] = {0};

    // Both callback calls should fill the buffers successfully.
    REQUIRE(SignalBridge::randomFunc(first, sizeof(first), nullptr) == SG_SUCCESS);
    REQUIRE(SignalBridge::randomFunc(second, sizeof(second), nullptr) == SG_SUCCESS);

    // Two independent 32-byte random buffers should almost never match in full.
    REQUIRE(std::memcmp(first, second, sizeof(first)) != 0);
}

TEST_CASE("randomFunc handles empty and invalid output buffers", "[bridge][edge]")
{
    // A zero-length request writes nothing, so a null output pointer is valid.
    REQUIRE(SignalBridge::randomFunc(nullptr, 0, nullptr) == SG_SUCCESS);

    // A non-zero request needs a valid pointer as the destination for its bytes.
    REQUIRE(SignalBridge::randomFunc(nullptr, 5, nullptr) == SG_ERR_INVAL);
}

TEST_CASE("CBC callbacks match the NIST vector and restore the plaintext", "[bridge]")
{
    signal_buffer *rawEncrypted = nullptr;
    int result = SignalBridge::encryptFunc(&rawEncrypted, SG_CIPHER_AES_CBC_PKCS5,
                                         kKey.data(), kKey.size(),
                                         kIv.data(), kIv.size(),
                                         kPlain.data(), kPlain.size(),
                                         nullptr);
    SignalBufferPtr encrypted(rawEncrypted, signal_buffer_free);
    REQUIRE(result == SG_SUCCESS);
    REQUIRE(encrypted != nullptr);
    // Check the exact NIST ciphertext, not just that decryption reverses encryption.
    REQUIRE(toBytes(encrypted.get()) == kCipher);

    signal_buffer *rawDecrypted = nullptr;
    result = SignalBridge::decryptFunc(&rawDecrypted, SG_CIPHER_AES_CBC_PKCS5,
                                       kKey.data(), kKey.size(),
                                       kIv.data(), kIv.size(),
                                       signal_buffer_data(encrypted.get()),
                                       signal_buffer_len(encrypted.get()),
                                       nullptr);
    SignalBufferPtr decrypted(rawDecrypted, signal_buffer_bzero_free);
    REQUIRE(result == SG_SUCCESS);
    REQUIRE(decrypted != nullptr);
    REQUIRE(toBytes(decrypted.get()) == kPlain);
}

TEST_CASE("CBC callbacks handle an empty plaintext", "[bridge][edge]")
{
    signal_buffer *rawEncrypted = nullptr;
    int result = SignalBridge::encryptFunc(&rawEncrypted, SG_CIPHER_AES_CBC_PKCS5,
                                           kKey.data(), kKey.size(),
                                           kIv.data(), kIv.size(),
                                           nullptr, 0, nullptr);
    SignalBufferPtr encrypted(rawEncrypted, signal_buffer_free);
    REQUIRE(result == SG_SUCCESS);
    REQUIRE(encrypted != nullptr);

    // CBC always adds padding; an empty plaintext becomes one full padding block.
    REQUIRE(signal_buffer_len(encrypted.get()) == 16);

    signal_buffer *rawDecrypted = nullptr;
    result = SignalBridge::decryptFunc(&rawDecrypted, SG_CIPHER_AES_CBC_PKCS5,
                                       kKey.data(), kKey.size(),
                                       kIv.data(), kIv.size(),
                                       signal_buffer_data(encrypted.get()),
                                       signal_buffer_len(encrypted.get()),
                                       nullptr);
    SignalBufferPtr decrypted(rawDecrypted, signal_buffer_bzero_free);
    REQUIRE(result == SG_SUCCESS);
    REQUIRE(decrypted != nullptr);
    REQUIRE(signal_buffer_len(decrypted.get()) == 0);
}

TEST_CASE("CBC callbacks reject unsupported ciphers and invalid key lengths", "[bridge][negative]")
{
    signal_buffer *output = nullptr;

    // This bridge supports CBC only, so a request for CTR must be rejected.
    int result = SignalBridge::encryptFunc(&output, SG_CIPHER_AES_CTR_NOPADDING,
                                           kKey.data(), kKey.size(),
                                           kIv.data(), kIv.size(),
                                           kPlain.data(), kPlain.size(), nullptr);
    REQUIRE(result == SG_ERR_INVAL);
    REQUIRE(output == nullptr);

    // AES-256 requires a 32-byte key. The callback must convert the crypto error
    // into a libsignal error code and leave the output buffer unset.
    result = SignalBridge::encryptFunc(&output, SG_CIPHER_AES_CBC_PKCS5,
                                       kKey.data(), 16,
                                       kIv.data(), kIv.size(),
                                       kPlain.data(), kPlain.size(), nullptr);
    REQUIRE(result < 0);
    REQUIRE(output == nullptr);
}

TEST_CASE("decryptFunc converts invalid CBC padding into an error code", "[bridge][negative]")
{
    Bytes corrupted = kCipher;
    // Change a byte in the previous block that affects the final padding byte
    // during decryption. This makes the padding invalid.
    corrupted[corrupted.size() - 17] ^= 0x01;

    signal_buffer *output = nullptr;
    int result = 0;

    // A decryption error must not let a C++ exception escape through the C callback.
    REQUIRE_NOTHROW(result = SignalBridge::decryptFunc(&output, SG_CIPHER_AES_CBC_PKCS5,
                                                       kKey.data(), kKey.size(),
                                                       kIv.data(), kIv.size(),
                                                       corrupted.data(), corrupted.size(),
                                                       nullptr));
    REQUIRE(result < 0);
    REQUIRE(output == nullptr);
}
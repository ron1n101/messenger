#include "catch_amalgamated.hpp"
#include <string>
#include "crypto/diffie_helman.h"
#include "crypto/crypto_exception.h"
#include "crypto/helper.h"


TEST_CASE("bytesFromHex converts hex string correctly", "[helpers]")
{
    std::string hex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    Bytes expectedBytes = {0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                           0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                           0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                           0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};

    Bytes result = bytesFromHex(hex);
    REQUIRE(result == expectedBytes);
}

TEST_CASE("X25519 shared secret matcher RFC 7748 test vectors (Alice -> Bob)", "[DH]")
{
    Bytes alicePrivateKey = bytesFromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    Bytes bobPublicKey = bytesFromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    Bytes expectedSharedSecret = bytesFromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    Bytes result = CryptoUtils_DH::generateSharedSecret(alicePrivateKey, bobPublicKey);
    REQUIRE(result == expectedSharedSecret);
}   

TEST_CASE("X25519 shared secret matcher RFC 7748 test vectors (Bob -> Alice)", "[DH]")
{
    Bytes bobPrivateKey = bytesFromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    Bytes alicePublicKey = bytesFromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    Bytes expectedSharedSecret = bytesFromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    Bytes result = CryptoUtils_DH::generateSharedSecret(bobPrivateKey, alicePublicKey);
    REQUIRE(result == expectedSharedSecret);
}

TEST_CASE("X25519 shared secret throws on invalid private key length", "[DH][negative]")
{
    Bytes invalidPrivateKey(10, 0x01);
    Bytes validPeerPublicKey(32, 0x02);

    REQUIRE_THROWS_AS(CryptoUtils_DH::generateSharedSecret(invalidPrivateKey, validPeerPublicKey), CryptoException);
}

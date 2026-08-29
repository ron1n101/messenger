#include "catch_amalgamated.hpp"
#include "crypto/keys.h"

TEST_CASE ("X25519 key pair has correct lengths", "[keys]")
{
    KeyPair kp = CryptoUtils::generateX25519KeyPair();
    REQUIRE(kp.publicKey.size() == 32);
    REQUIRE(kp.privateKey.size() == 32);
}

TEST_CASE ("Ed25519 key pair has correct lengths", "[keys]")
{
    KeyPair kp = CryptoUtils::generateEd25519keyPair();
    REQUIRE(kp.publicKey.size() == 32);
    REQUIRE(kp.privateKey.size() == 32);
}

TEST_CASE ("Both X25519 key pairs not identicals", "[keys]")
{
    KeyPair kp1 = CryptoUtils::generateX25519KeyPair();
    KeyPair kp2 = CryptoUtils::generateEd25519keyPair();
    REQUIRE(kp1.publicKey != kp2.publicKey);
    REQUIRE(kp1.privateKey != kp2.privateKey);
}

TEST_CASE ("SecureRandomBytes has produces different output each time", "[random]")
{
    Bytes r1 = CryptoUtils::secureRandomBytes(32);
    Bytes r2 = CryptoUtils::secureRandomBytes(32);

    REQUIRE(r1.size() == 32);
    REQUIRE(r2.size() == 32);
    REQUIRE(r1 != r2);
}
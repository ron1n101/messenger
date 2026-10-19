#include "catch_amalgamated.hpp"
#include "crypto/hmac.h"
#include "crypto/crypto_exception.h"
#include "crypto/helper.h"   // bytesFromHex
#include <string>

namespace {
    Bytes bytesFromString(const std::string &s) { return Bytes(s.begin(), s.end()); }
}

TEST_CASE("HMAC-SHA256 matches RFC 4231 Test Case 1", "[hmac]")
{
    const Bytes key(20, 0x0b);
    const Bytes data = bytesFromString("Hi There");
    const Bytes expected = bytesFromHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    // ЗАДАНИЕ: expected = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
}

TEST_CASE("HMAC-SHA256 matches RFC 4231 Test Case 2 (key shorter than block)", "[hmac]")
{
    const Bytes key = bytesFromString("Jefe");
    const Bytes data = bytesFromString("what do ya want for nothing?");
    // expected = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    const Bytes expected = bytesFromHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
}

TEST_CASE("HMAC-SHA256 matches RFC 4231 Test Case 3", "[hmac]")
{
    const Bytes key(20, 0xaa);
    const Bytes data(50, 0xdd);
    const Bytes expected = bytesFromHex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
    // expected = 773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
}

TEST_CASE("HMAC-SHA256 matches RFC 4231 Test Case 4", "[hmac]")
{
    // Собираем ключ из последовательных байтов: 0x01, 0x02, ..., 0x19.
    Bytes key;
    for (int value = 0x01; value <= 0x19; ++value)
    {
        key.push_back(static_cast<Bytes::value_type>(value));
    }

    // Входное сообщение состоит из 50 одинаковых байтов 0xcd.
    const Bytes data(50, 0xcd);

    // Эталонный HMAC-SHA256 из RFC 4231, Test Case 4.
    const Bytes expected = bytesFromHex(
        "82558a389a443c0ea4cc819899f2083a"
        "85f0faa3e578f8077a2e3ff46729665b"
    );

    // Сравниваем результат реализации с эталонным 32-байтовым HMAC.
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
}

TEST_CASE("HMAC-SHA256 matches RFC 4231 Test Case 6 (key longer than block)", "[hmac]")
{
    const Bytes key(131, 0xaa);
    const Bytes data = bytesFromString("Test Using Larger Than Block-Size Key - Hash Key First");
    const Bytes expected = bytesFromHex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
    // expected = 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
}

TEST_CASE("HMAC-SHA256 matches RFC 4231 Test Case 7", "[hmac]")
{
    const Bytes key(131, 0xaa);
    const Bytes data = bytesFromString(
        "This is a test using a larger than block-size key and a larger than "
        "block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    const Bytes expected = bytesFromHex("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
    // expected = 9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
}

TEST_CASE("HMAC-SHA256 with empty key and data works", "[hmac][edge]")
{
    // key пустой, data = "abc"
    const Bytes key;
    const Bytes data = bytesFromString("abc");
    const Bytes expected = bytesFromHex("fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351");
    REQUIRE(CryptoUtils::hmacSha256(key, data) == expected);
    // expected = fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351
    // ЗАДАНИЕ: добавь ещё случай, где пустой data.
    //          Эталон посчитай сам в Python: hmac.new(b"k", b"", hashlib.sha256).hexdigest()
}

TEST_CASE("HMAC-SHA256 verify", "[hmac][negative]")
{
    const Bytes key = bytesFromString("secret");
    const Bytes data = bytesFromString("message");
    const Bytes mac = CryptoUtils::hmacSha256(key, data);

    SECTION("valid mac accepted")
    {
        REQUIRE(CryptoUtils::hmacSha256Verify(key, data, mac));
    }
    
    SECTION("modified data rejected")  
    {   // { /* измени бит data -> REQUIRE_FALSE */ }
        Bytes modifiedData = data;
        modifiedData[0] ^= 0x01;
        REQUIRE_FALSE(CryptoUtils::hmacSha256Verify(key, modifiedData, mac));
    }
    
    
    SECTION("modified mac rejected")   
    {   // { /* измени бит mac -> REQUIRE_FALSE */ }
        Bytes modifiedMac = mac;
        modifiedMac[0] = 0x01;
        REQUIRE_FALSE(CryptoUtils::hmacSha256Verify(key, data, modifiedMac));
    }
    
    
    SECTION("different key rejected")
    {// { /* другой ключ -> REQUIRE_FALSE */ }
        const Bytes anotherKey = bytesFromString("another secret");
        REQUIRE_FALSE(CryptoUtils::hmacSha256Verify(anotherKey, data, mac));
    }
    
    
    SECTION("wrong length rejected")   
    {// { /* mac.resize(31) и mac.resize(33) -> REQUIRE_FALSE */ }
        Bytes shortMac = mac;
        shortMac.resize(31);
        REQUIRE_FALSE(CryptoUtils::hmacSha256Verify(key, data, shortMac));

        Bytes longMac = mac;
        longMac.resize(33);
        REQUIRE_FALSE(CryptoUtils::hmacSha256Verify(key, data, longMac));
    }
    
}
#include "catch_amalgamated.hpp"
#include "crypto/kdf.h"
#include "crypto/helper.h"

TEST_CASE("HKDF matches RFC 5869 Test Case 1", "[kdf]")
{
    // Тест-вектор из RFC 5869, Appendix A.1
    Bytes ikm  = bytesFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    Bytes salt = bytesFromHex("000102030405060708090a0b0c");
    Bytes info = bytesFromHex("f0f1f2f3f4f5f6f7f8f9");
    int L = 42;

    Bytes expectedOkm = bytesFromHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    Bytes result = CryptoUtils::hkdf(ikm, salt, info, L);

    REQUIRE(result.size() == L);   // проверь и размер тоже, не только содержимое
    REQUIRE(result == expectedOkm);
}


TEST_CASE("HKDF matches RFC 5869 Test Case 2", "[kdf]")
{
    // ЗАДАНИЕ: возьми Test Case 2 из RFC 5869 (там длинные входные данные и L = 82).
    // Он полезен именно тем, что проверяет работу на ДРУГОЙ длине выхода —
    // если бы ты случайно захардкодил 42 где-то внутри, этот тест бы это поймал.
    Bytes ikm = bytesFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    Bytes salt = bytesFromHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    Bytes info = bytesFromHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    int L = 82;

    Bytes expectedOkm = bytesFromHex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    Bytes result = CryptoUtils::hkdf(ikm, salt, info, L);

    REQUIRE(result.size() == L);
    REQUIRE(result == expectedOkm);

}


TEST_CASE("HKDF produces different output for different info", "[kdf]")
{
    // ЗАДАНИЕ: это важный СМЫСЛОВОЙ тест, не из RFC.
    // Возьми ОДИНАКОВЫЕ ikm и salt, но РАЗНЫЕ info — результаты должны отличаться.
    //
    // Почему это критично: именно на этом свойстве построен весь X3DH/Double Ratchet —
    // из одного DH-секрета выводится несколько НЕЗАВИСИМЫХ ключей
    // (например, "ключ для шифрования" и "ключ для аутентификации"),
    // и они различаются ТОЛЬКО значением info.
    // Если бы info не влиял на результат — все эти ключи были бы одинаковыми,
    // и вся схема безопасности развалилась бы.

    Bytes ikm  = bytesFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
    Bytes salt = bytesFromHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    Bytes info1 = bytesFromHex("656e6372797074696f6e");
    Bytes info2 = bytesFromHex("61757468656e7469636174696f6e");
    int L = 32;

    Bytes out1 = CryptoUtils::hkdf(ikm, salt, info1, L);
    Bytes out2 = CryptoUtils::hkdf(ikm, salt, info2, L);


    REQUIRE(out1 != out2);
}
TEST_CASE("HKDF produces requested output length", "[kdf]")
{
    // ЗАДАНИЕ: проверь, что при запросе разных длин (например, 16, 32, 64)
    // функция реально возвращает Bytes именно такого размера.

    Bytes ikm = bytesFromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    Bytes salt = bytesFromHex("000102030405060708090a0b0c");
    Bytes info = bytesFromHex("f0f1f2f3f4f5f6f7f8f9");

    std::vector<int> lengths = {16, 32, 64};
    for (int L : lengths)
    {
        Bytes results = CryptoUtils::hkdf(ikm, salt, info, L);
        REQUIRE(results.size() == static_cast<int>(L));
    }
}    
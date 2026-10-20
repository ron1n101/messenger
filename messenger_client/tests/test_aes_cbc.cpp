#include "catch_amalgamated.hpp"
#include "crypto/aes_cbc.h"
#include "crypto/crypto_exception.h"
#include "crypto/keys.h"      // secureRandomBytes
#include "crypto/helper.h"    // bytesFromHex
#include <cstddef>
#include <initializer_list>

// ---------------------------------------------------------------------
// Общие данные из NIST SP 800-38A, F.2.5 (AES-256-CBC).
// Вынесены в функции, чтобы не копировать длинные строки в каждый тест.
// ---------------------------------------------------------------------
namespace {
    Bytes nistKey()
    {
        return bytesFromHex("603deb1015ca71be2b73aef0857d7781"
                            "1f352c073b6108d72d9810a30914dff4");
    }

    Bytes nistIv()
    {
        return bytesFromHex("000102030405060708090a0b0c0d0e0f");
    }

    // 64 байта = 4 блока по 16.
    Bytes nistPlainText()
    {
        return bytesFromHex("6bc1bee22e409f96e93d7e117393172a"
                            "ae2d8a571e03ac9c9eb76fac45af8e51"
                            "30c81c46a35ce411e5fbc1191a0a52ef"
                            "f69f2445df4f9b17ad2b417be66c3710");
    }

    // 80 байт = 4 блока из NIST + 1 блок дополнения.
    // Первые 64 байта совпадают с документом NIST, последние 16 — дополнение.
    Bytes nistCipherText()
    {
        return bytesFromHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                            "9cfc4e967edb808d679f777bc6702c7d"
                            "39f23369a9d9bacfa530e26304231461"
                            "b2eb05e2c39be9fcda6c19078c6a9d1b"
                            "3f461796d6b0d6b2e0c2a72b4d80e644");
    }
}

// =====================================================================
// ГРУППА 1. Эталонные векторы: шифруем и сравниваем с заранее известным ответом.
// Каждый тест проверяет и обратный путь: расшифровка даёт исходный текст.
// =====================================================================

TEST_CASE("AES-CBC matches NIST vector (64 bytes)", "[aes_cbc]")
{
    const Bytes key = nistKey();
    const Bytes iv = nistIv();
    const Bytes plainText = nistPlainText();

    // ВПИШИ: const Bytes result = вызов aesCbcEncrypt с key, iv, plainText;
    const Bytes result = CryptoUtils::aesCbcEncrypt(key, iv, plainText);

    // ВПИШИ: REQUIRE, что result равен nistCipherText()
    // Сверяемся с готовым ответом, чтобы проверить именно правильность шифрования.
    REQUIRE(result == nistCipherText());
    // ВПИШИ: REQUIRE, что result.size() == 80 (64 данных + 16 дополнения)
    REQUIRE(result.size() == 80);
    // ВПИШИ: REQUIRE, что aesCbcDecrypt(key, iv, result) равен plainText
    REQUIRE(CryptoUtils::aesCbcDecrypt(key, iv, result) == plainText);
}

TEST_CASE("AES-CBC matches vector (one full block)", "[aes_cbc]")
{
    const Bytes key = nistKey();
    const Bytes iv = nistIv();
    // Первый блок текста NIST — ровно 16 байт.
    const Bytes plainText = bytesFromHex("6bc1bee22e409f96e93d7e117393172a");
    const Bytes expected = bytesFromHex("f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                                        "485a5c81519cf378fa36d42b8547edc0");

    // ВПИШИ: зашифровать, сравнить с expected, расшифровать и сравнить с plainText.
    // Три строки — по образцу теста выше.
    const Bytes result = CryptoUtils::aesCbcEncrypt(key, iv, plainText);
    REQUIRE(result == expected);
    REQUIRE(CryptoUtils::aesCbcDecrypt(key, iv, result) == plainText);
}

TEST_CASE("AES-CBC matches vector (empty plaintext)", "[aes_cbc][edge]")
{
    const Bytes key = nistKey();
    const Bytes iv = nistIv();
    const Bytes plainText;   // пустой
    // Даже у пустого сообщения есть один блок — целиком дополнение.
    const Bytes expected = bytesFromHex("7e9248e5d829ca7593f0c549db2f5b8c");

    // ВПИШИ: те же три проверки.
    // В последней проверь, что расшифровка даёт ПУСТОЙ результат: REQUIRE(....empty());
    const Bytes result = CryptoUtils::aesCbcEncrypt(key, iv, plainText);
    REQUIRE(result == expected);
    REQUIRE(result.size() == 16);
    REQUIRE(CryptoUtils::aesCbcDecrypt(key, iv, result).empty());
}

TEST_CASE("AES-CBC matches vector (5 bytes, partial block)", "[aes_cbc][edge]")
{
    const Bytes key = nistKey();
    const Bytes iv = nistIv();
    const Bytes plainText = bytesFromHex("6bc1bee22e");   // 5 байт
    const Bytes expected = bytesFromHex("117fb057f4728629cee1de6a7afe3370");

    // ВПИШИ: те же три проверки.
    const Bytes result = CryptoUtils::aesCbcEncrypt(key, iv, plainText);
    REQUIRE(result == expected);
    REQUIRE(CryptoUtils::aesCbcDecrypt(key, iv, result) == plainText);
}

// =====================================================================
// ГРУППА 2. Туда и обратно со случайными данными.
// ЗАЧЕМ: проверяем размеры вокруг границы блока (15, 16, 17) —
// именно там чаще всего ошибаются с дополнением.
// =====================================================================

TEST_CASE("AES-CBC roundtrip for sizes around block boundary", "[aes_cbc]")
{
    const Bytes key = CryptoUtils::secureRandomBytes(32);
    const Bytes iv = CryptoUtils::secureRandomBytes(16);

    for (const std::size_t length : {0, 1, 15, 16, 17, 100})
    {
        // Случайный текст нужной длины. Для 0 берём пустой вектор,
        // т.к. secureRandomBytes(0) может вести себя по-разному.
        const Bytes plainText = (length == 0)
            ? Bytes{}
            : CryptoUtils::secureRandomBytes(static_cast<int>(length));

        // ВПИШИ: const Bytes cipherText = зашифровать plainText;
        const Bytes cipherText = CryptoUtils::aesCbcEncrypt(key, iv, plainText);
        // ВПИШИ: REQUIRE, что cipherText.size() % 16 == 0 (всегда целые блоки)
        REQUIRE(cipherText.size() % 16 == 0);
        // ВПИШИ: REQUIRE, что расшифровка cipherText равна plainText
        // Этот тест проверяет, что после шифрования и обратной расшифровки байты не меняются.
        REQUIRE(CryptoUtils::aesCbcDecrypt(key, iv, cipherText) == plainText);
    }
}

TEST_CASE("AES-CBC ciphertext length includes padding", "[aes_cbc]")
{
    const Bytes key = CryptoUtils::secureRandomBytes(32);
    const Bytes iv = CryptoUtils::secureRandomBytes(16);

    // 15 байт -> дополняется 1 байтом -> 16.
    // ВПИШИ: REQUIRE, что aesCbcEncrypt(key, iv, Bytes(15, 0x00)).size() == 16
    REQUIRE(CryptoUtils::aesCbcEncrypt(key, iv, Bytes(15, 0x00)).size() == 16);

    // 16 байт -> целый блок, но дополнение ВСЁ РАВНО добавляется целым блоком -> 32.
    // ЗАЧЕМ так: иначе при расшифровке нельзя понять, было дополнение или нет.
    // ВПИШИ: REQUIRE, что aesCbcEncrypt(key, iv, Bytes(16, 0x00)).size() == 32
    REQUIRE(CryptoUtils::aesCbcEncrypt(key, iv, Bytes(16, 0x00)).size() == 32);
}

// =====================================================================
// ГРУППА 3. Неверные входные данные: функции должны бросить исключение.
// =====================================================================

TEST_CASE("AES-CBC rejects wrong key and IV length", "[aes_cbc][negative]")
{
    const Bytes goodKey(32, 0x01);
    const Bytes goodIv(16, 0x02);
    const Bytes plainText(10, 0x03);
    const Bytes cipherText = CryptoUtils::aesCbcEncrypt(goodKey, goodIv, plainText);

    for (const std::size_t keyLength : {16, 31, 33})
    {
        const Bytes badKey(keyLength, 0x01);
        // ВПИШИ: REQUIRE_THROWS_AS(шифрование с badKey, goodIv, plainText, CryptoException);
        REQUIRE_THROWS_AS(CryptoUtils::aesCbcEncrypt(badKey, goodIv, plainText), CryptoException);
        // ВПИШИ: REQUIRE_THROWS_AS(расшифровка с badKey, goodIv, cipherText, CryptoException);
        REQUIRE_THROWS_AS(CryptoUtils::aesCbcDecrypt(badKey, goodIv, cipherText), CryptoException);
    }

    for (const std::size_t ivLength : {0, 12, 17})
    {
        const Bytes badIv(ivLength, 0x02);
        // ВПИШИ: то же самое, но с goodKey и badIv.
        REQUIRE_THROWS_AS(CryptoUtils::aesCbcEncrypt(goodKey, badIv, plainText), CryptoException);
        REQUIRE_THROWS_AS(CryptoUtils::aesCbcDecrypt(goodKey, badIv, cipherText), CryptoException);
    }
}

TEST_CASE("AES-CBC decrypt rejects wrong ciphertext length", "[aes_cbc][negative]")
{
    const Bytes key(32, 0x01);
    const Bytes iv(16, 0x02);

    // 0 — пусто; 15 и 17 — не кратны 16.
    for (const std::size_t length : {0, 15, 17})
    {
        const Bytes badCipherText(length, 0xAA);
        // ВПИШИ: REQUIRE_THROWS_AS(расшифровка badCipherText, CryptoException);
        REQUIRE_THROWS_AS(CryptoUtils::aesCbcDecrypt(key, iv, badCipherText), CryptoException);
    }
}

// =====================================================================
// ГРУППА 4. Порча данных.
// =====================================================================

TEST_CASE("AES-CBC decrypt rejects corrupted padding", "[aes_cbc][negative]")
{
    Bytes cipherText = nistCipherText();
    // Меняем последний байт ПРЕДЫДУЩЕГО блока: после расшифровки последний байт
    // дополнения изменится с 0x10 на 0x11, поэтому ошибка будет гарантированной.
    // ВПИШИ: испортить последний байт предыдущего блока.
    cipherText[cipherText.size() - 17] ^= 0x01;

    // ВПИШИ: REQUIRE_THROWS_AS(расшифровка с nistKey(), nistIv(), cipherText, CryptoException);
    REQUIRE_THROWS_AS(CryptoUtils::aesCbcDecrypt(nistKey(), nistIv(), cipherText), CryptoException);
}

TEST_CASE("AES-CBC decrypt with wrong key fails", "[aes_cbc][negative]")
{
    Bytes wrongKey = nistKey();
    // ВПИШИ: поменять один бит в wrongKey[0] (через ^= 0x01)
    wrongKey[0] ^= 0x01;

    // ВПИШИ: REQUIRE_THROWS_AS(расшифровка с wrongKey, nistIv(), nistCipherText(), CryptoException);
    REQUIRE_THROWS_AS(CryptoUtils::aesCbcDecrypt(wrongKey, nistIv(), nistCipherText()), CryptoException);
}

// =====================================================================
// ГРУППА 5. Урок: CBC НЕ ЗАМЕЧАЕТ подмену.
// ЗАЧЕМ этот тест: он показывает, почему CBC всегда нужен в паре с HMAC.
// =====================================================================

TEST_CASE("AES-CBC alone does NOT detect tampering in first block", "[aes_cbc][lesson]")
{
    Bytes cipherText = nistCipherText();
    // Меняем ПЕРВЫЙ байт шифротекста.
    // ВПИШИ: cipherText[0] ^= 0x01;
    cipherText[0] ^= 0x01;

    // Ошибки НЕ будет: дополнение в последнем блоке осталось целым.
    Bytes result;
    // ВПИШИ: REQUIRE_NOTHROW(result = расшифровка с nistKey(), nistIv(), cipherText);
    REQUIRE_NOTHROW(result = CryptoUtils::aesCbcDecrypt(nistKey(), nistIv(), cipherText));

    // Длина правильная — подделку по длине не заметить.
    // ВПИШИ: REQUIRE, что result.size() == 64
    REQUIRE(result.size() == 64);

    // Но текст уже не тот: первый блок превратился в мусор.
    // ВПИШИ: REQUIRE, что result != nistPlainText()
    REQUIRE(result != nistPlainText());

    // А последние два блока (байты 32..63) остались нетронутыми —
    // атакующий портит только то, что хочет.
    const Bytes original = nistPlainText();
    for (std::size_t i = 32; i < 64; ++i)
    {
        // ВПИШИ: REQUIRE(result[i] == original[i]);
        REQUIRE(result[i] == original[i]);
    }

    // ВПИШИ свой комментарий: почему этот тест — аргумент за HMAC (одно-два предложения).
    // CBC не замечает такую подмену: расшифровка проходит, хотя результат изменился.
    // HMAC позволяет проверить целостность и отклонить изменённый шифротекст.
}
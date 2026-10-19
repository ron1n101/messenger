#include "catch_amalgamated.hpp"
#include "crypto/aead.h"
#include "crypto/aead_internal.h"
#include "crypto/keys.h"
#include "crypto/crypto_exception.h"
#include "crypto/helper.h"   // bytesFromHex
#include <cstddef>

// Проверяем шифрование по официальному тест-вектору AES-GCM.
// Фиксированные ключ и IV нужны, чтобы результат каждый раз был одинаковым.
TEST_CASE("AES-GCM matches Test Case 13 (empty plaintext)", "[aead]")
{
	// Тест-вектор 13: ключ и IV нулевые, открытый текст и AAD пустые.
	const Bytes key(32, 0x00);
	const Bytes iv(12, 0x00);
	const Bytes plainText;
	const Bytes aad;
	// Для пустого текста шифротекст тоже пустой; проверяем известный тег.
	const Bytes expectedTag = bytesFromHex("530f8afbc74536b9a963b4f1c4cb738b");

	// WithIv позволяет задать фиксированный IV вместо случайного.
	const CryptoUtils::AeadCipherText result =
		CryptoInternal::aesGcmEncryptWithIv(key, iv, plainText, aad);

	// Проверяем, что IV сохранён, шифротекст пуст, а тег совпал с эталоном.
	REQUIRE(result.iv == iv);
	REQUIRE(result.cipherText.empty());
	REQUIRE(result.tag == expectedTag);
}

// Проверяем AES-GCM на эталонном векторе с одним блоком открытого текста.
TEST_CASE("AES-GCM matches Test Case 14", "[aead]")
{
	// Тест-вектор 14: 32-байтовый ключ, 12-байтовый IV и 16 нулевых байтов текста.
	const Bytes key(32, 0x00);
	const Bytes iv(12, 0x00);
	const Bytes plainText(16, 0x00);
	const Bytes aad;
	// Ожидаемые значения опубликованы в тестовом векторе AES-GCM.
	const Bytes expectedCipherText = bytesFromHex("cea7403d4d606b6e074ec5d3baf39d18");
	const Bytes expectedTag = bytesFromHex("d0d1c8a799996bf0265b98b5d48ab919");

	// Шифруем с теми же фиксированными параметрами, что и в векторе.
	const CryptoUtils::AeadCipherText result =
		CryptoInternal::aesGcmEncryptWithIv(key, iv, plainText, aad);

	// Сравнение с эталоном проверяет точные результаты, а расшифрование — обратный путь.
	REQUIRE(result.cipherText == expectedCipherText);
	REQUIRE(result.tag == expectedTag);
	REQUIRE(CryptoUtils::aesGcmDecrypt(key, result, aad) == plainText);
}

// Проверяем вектор с более длинным текстом и дополнительными аутентифицируемыми данными.
TEST_CASE("AES-GCM matches Test Case 16 (with AAD)", "[aead]")
{
	// bytesFromHex переводит записанные шестнадцатеричные байты в Bytes.
	// Ключ, IV, текст и AAD здесь заданы эталонным вектором.
	const Bytes key = bytesFromHex(
		"feffe9928665731c6d6a8f9467308308"
		"feffe9928665731c6d6a8f9467308308"
	);
	const Bytes iv = bytesFromHex("cafebabefacedbaddecaf888");
	const Bytes plainText = bytesFromHex(
		"d9313225f88406e5a55909c5aff5269a"
		"86a7a9531534f7da2e4c303d8a318a72"
		"1c3c0c95956809532fcf0e2449a6b525"
		"b16aedf5aa0de657ba637b39"
	);
	const Bytes aad = bytesFromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
	const Bytes expectedCipherText = bytesFromHex(
		"522dc1f099567d07f47f37a32a84427d"
		"643a8cdcbfe5c0c97598a2bd2555d1aa"
		"8cb08e48590dbb3da7b08b1056828838"
		"c5f61e6393ba7a0abcc9f662"
	);
	const Bytes expectedTag = bytesFromHex("76fc6ece0f4e1768cddf8853bb2d551b");

	// Фиксированный IV позволяет сравнить результат с точным эталоном.
	const CryptoUtils::AeadCipherText result =
		CryptoInternal::aesGcmEncryptWithIv(key, iv, plainText, aad);

	// Проверяем шифротекст и тег, а затем убеждаемся, что те же AAD и ключ расшифровывают текст.
	REQUIRE(result.cipherText == expectedCipherText);
	REQUIRE(result.tag == expectedTag);
	REQUIRE(CryptoUtils::aesGcmDecrypt(key, result, aad) == plainText);
}

// Проверяем обычный сценарий: случайный ключ, шифрование и последующая расшифровка.
TEST_CASE("AES-GCM roundtrip with random key", "[aead]")
{
	// Генерируем ключ правильной для AES-256 длины и задаём данные для защиты.
	const Bytes key = CryptoUtils::secureRandomBytes(32);
	const Bytes plainText = bytesFromHex("00112233445566778899aabbccddeeff");
	const Bytes aad = bytesFromHex("a0a1a2a3a4a5");

	// Публичная функция сама создаёт случайный IV; расшифровываем результат тем же ключом и AAD.
	const CryptoUtils::AeadCipherText encrypted =
		CryptoUtils::aesGcmEncrypt(key, plainText, aad);

	// После полного цикла исходные байты должны восстановиться без изменений.
	REQUIRE(CryptoUtils::aesGcmDecrypt(key, encrypted, aad) == plainText);
}

// Проверяем граничный случай: шифровать и расшифровывать нечего, но тег всё равно создаётся.
TEST_CASE("AES-GCM roundtrip with empty plaintext and empty AAD", "[aead]")
{
	const Bytes key = CryptoUtils::secureRandomBytes(32);
	const Bytes plainText;
	const Bytes aad;

	// Даже для пустых входов формируется результат AES-GCM с IV и тегом.
	const CryptoUtils::AeadCipherText encrypted =
		CryptoUtils::aesGcmEncrypt(key, plainText, aad);

	// Шифротекст должен остаться пустым, а расшифровка вернуть пустой plaintext.
	REQUIRE(encrypted.cipherText.empty());
	REQUIRE(CryptoUtils::aesGcmDecrypt(key, encrypted, aad).empty());
}

// Проверяем, что новое шифрование того же сообщения использует новый случайный IV.
TEST_CASE("AES-GCM two encryptions of same data differ (fresh IV)", "[aead]")
{
	const Bytes key = CryptoUtils::secureRandomBytes(32);
	const Bytes plainText = bytesFromHex("0102030405060708090a0b0c0d0e0f");
	const Bytes aad = bytesFromHex("10111213");

	// Шифруем одни и те же данные дважды одним ключом.
	const CryptoUtils::AeadCipherText first =
		CryptoUtils::aesGcmEncrypt(key, plainText, aad);
	const CryptoUtils::AeadCipherText second =
		CryptoUtils::aesGcmEncrypt(key, plainText, aad);

	// Разные IV должны приводить к разным шифротекстам.
	REQUIRE(first.iv != second.iv);
	REQUIRE(first.cipherText != second.cipherText);
}

// Проверяем, что расшифрование отвергает данные, если нарушена их подлинность.
TEST_CASE("AES-GCM decrypt rejects tampering", "[aead][negative]")
{
	const Bytes key = CryptoUtils::secureRandomBytes(32);
	const Bytes plainText = bytesFromHex("00112233445566778899aabbccddeeff");
	const Bytes aad = bytesFromHex("a0a1a2a3a4a5");
	const CryptoUtils::AeadCipherText encrypted =
		CryptoUtils::aesGcmEncrypt(key, plainText, aad);

	// Catch2 запускает каждую SECTION отдельно с заново созданным исходным шифротекстом.
	SECTION("modified ciphertext")
	{
		CryptoUtils::AeadCipherText modified = encrypted;
		// XOR с 1 переключает один бит: тег после этого не должен пройти проверку.
		modified.cipherText[0] ^= 0x01;
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(key, modified, aad), CryptoException);
	}

	SECTION("modified tag")
	{
		CryptoUtils::AeadCipherText modified = encrypted;
		// Меняем один бит тега, чтобы проверить обнаружение повреждённого тега.
		modified.tag[0] ^= 0x01;
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(key, modified, aad), CryptoException);
	}

	SECTION("different AAD")
	{
		Bytes modifiedAad = aad;
		// AAD не шифруется, но защищается тегом; другое AAD должно вызвать отказ.
		modifiedAad[0] ^= 0x01;
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(key, encrypted, modifiedAad), CryptoException);
	}

	SECTION("different key")
	{
		Bytes modifiedKey = key;
		// Меняем один бит ключа: исходный тег больше не соответствует расшифрованию.
		modifiedKey[0] ^= 0x01;
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(modifiedKey, encrypted, aad), CryptoException);
	}
}

// AES-GCM использует тег длиной 16 байт; короткие и длинные теги должны отвергаться.
TEST_CASE("AES-GCM decrypt rejects truncated or extended tag", "[aead][negative]")
{
	const Bytes key = CryptoUtils::secureRandomBytes(32);
	const Bytes plainText = bytesFromHex("0011223344556677");
	const Bytes aad;
	const CryptoUtils::AeadCipherText encrypted =
		CryptoUtils::aesGcmEncrypt(key, plainText, aad);

	// Проверяем несколько некорректных размеров, включая слишком короткие и слишком длинный.
	for (const std::size_t tagLength : {1, 8, 15, 17})
	{
		CryptoUtils::AeadCipherText malformed = encrypted;
		// Обрезаем или расширяем копию тега, не меняя исходный корректный результат.
		malformed.tag.resize(tagLength);
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(key, malformed, aad), CryptoException);
	}
}

// Проверяем допустимые размеры AES-256-ключа и GCM-IV на входе обеих операций.
TEST_CASE("AES-GCM rejects wrong key and IV length", "[aead][negative]")
{
	const Bytes key(32, 0x2a);
	const Bytes iv(12, 0x3b);
	const Bytes plainText = bytesFromHex("01020304");
	const Bytes aad;
	const CryptoUtils::AeadCipherText encrypted =
		CryptoInternal::aesGcmEncryptWithIv(key, iv, plainText, aad);

	// Для AES-256 ключ обязан быть 32 байта; 16 и 31 байт должны вызвать CryptoException.
	for (const std::size_t keyLength : {16, 31})
	{
		const Bytes invalidKey(keyLength, 0x2a);
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmEncrypt(invalidKey, plainText, aad), CryptoException);
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(invalidKey, encrypted, aad), CryptoException);
	}

	// В этом интерфейсе IV обязан быть 12 байт; проверяем короткий и длинный варианты.
	for (const std::size_t ivLength : {8, 16})
	{
		const Bytes invalidIv(ivLength, 0x3b);
		REQUIRE_THROWS_AS(
			CryptoInternal::aesGcmEncryptWithIv(key, invalidIv, plainText, aad),
			CryptoException
		);

		// Тот же неверный IV проверяем и на входе расшифрования.
		CryptoUtils::AeadCipherText malformed = encrypted;
		malformed.iv = invalidIv;
		REQUIRE_THROWS_AS(CryptoUtils::aesGcmDecrypt(key, malformed, aad), CryptoException);
	}
}
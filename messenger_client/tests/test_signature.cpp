#include "catch_amalgamated.hpp"
#include <string>
#include "crypto/signature.h"
#include "crypto/crypto_exception.h"
#include "crypto/keys.h"
#include "crypto/helper.h"


TEST_CASE ("ED25519 sign and verify roundtrip with the generarated keys", "[signature]")
{

    // ШАГ 1: сгенерируй пару ключей через CryptoUtils::generateEd25519KeyPair()
    // ШАГ 2: подготовь произвольное сообщение (например, Bytes из строки "hello world")
    // ШАГ 3: подпиши сообщение приватным ключом через CryptoUtils::ed25519Sign
    // ШАГ 4: проверь подпись публичным ключом через CryptoUtils::ed25519Verify
    // ШАГ 5: REQUIRE, что результат — true

    KeyPair kp = CryptoUtils::generateEd25519keyPair();
    std::string hex = "48656c6c6f2c20576f726c6421";
    Bytes message = bytesFromHex(hex);
    Bytes signature = CryptoUtils_Signature::ed25519Sign(kp.privateKey, message);

    // bool isTrue = CryptoUtils_Signature::ed25519Verify(kp.publicKey, message, signature);
    // REQUIRE(isTrue == true);
    REQUIRE (CryptoUtils_Signature::ed25519Verify(kp.publicKey, message, signature));
    
}

TEST_CASE("Ed25519 signature matches RFC 8032 test vector", "[signature]")
{
    // ШАГ 1: возьми официальный тест-вектор из задания (SECRET KEY, PUBLIC KEY, SIGNATURE)
    // ШАГ 2: обрати внимание — MESSAGE пустое! Как будет выглядеть пустой Bytes?
    // ШАГ 3: подпиши пустое сообщение приватным ключом из вектора
    // ШАГ 4: сравни результат с ожидаемой подписью из RFC побайтово

    Bytes secretKey   = bytesFromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    Bytes emptyMessage = {};
    Bytes expectedSignature = bytesFromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    Bytes result = CryptoUtils_Signature::ed25519Sign(secretKey, emptyMessage);

    REQUIRE(result == expectedSignature);
}

TEST_CASE("Ed25519 verify returns true for valid RFC 8032 signature", "[signature]")
{
    // ШАГ 1: возьми PUBLIC KEY, MESSAGE и SIGNATURE из того же (или другого) тест-вектора RFC
    // ШАГ 2: вызови ed25519Verify и проверь, что результат — true

    Bytes publicKey = bytesFromHex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    Bytes message = {};
    Bytes signature = bytesFromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    REQUIRE(CryptoUtils_Signature::ed25519Verify(publicKey, message, signature));
}

TEST_CASE("Ed25519 verify returns false for tampered signature", "[signature][negative]")
{
    // ШАГ 1: сгенерируй ключи, подпиши сообщение (как в первом тесте)
    // ШАГ 2: испорти ОДИН байт в подписи (например: signature[0] ^= 0xFF;)
    // ШАГ 3: проверь, что ed25519Verify вернул false


    KeyPair kp = CryptoUtils::generateEd25519keyPair();
    Bytes message = bytesFromHex("48656c6c6f2c20576f726c6421");
    Bytes signature = CryptoUtils_Signature::ed25519Sign(kp.privateKey, message);
    signature[0] ^=0xff;
    Bytes incorrect_signature = signature;
    bool isValid = CryptoUtils_Signature::ed25519Verify(kp.publicKey, message, incorrect_signature);

    REQUIRE(isValid == false);
}


TEST_CASE("Ed25519 verify returns false when using wrong public key", "[signature][negative]")
{
    // ШАГ 1: сгенерируй ДВЕ разные пары ключей (kp1 и kp2)
    // ШАГ 2: подпиши сообщение приватным ключом ПЕРВОЙ пары
    // ШАГ 3: попробуй проверить подпись публичным ключом ВТОРОЙ пары
    // ШАГ 4: результат должен быть false

    KeyPair kp1 = CryptoUtils::generateEd25519keyPair();
    KeyPair kp2 = CryptoUtils::generateEd25519keyPair();

    Bytes message = bytesFromHex("48656c6c6f2c20576f726c6421");
    Bytes signature = CryptoUtils_Signature::ed25519Sign(kp1.privateKey, message);
    bool isValid = CryptoUtils_Signature::ed25519Verify(kp2.publicKey, message, signature);

    REQUIRE(isValid == false);

}

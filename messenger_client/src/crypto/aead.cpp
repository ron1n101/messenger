#include "aead.h"
#include "aead_internal.h"
#include "keys.h"
#include "secure_memory.h"
#include "openssl_raii.h"
#include "openssl_error.h"
#include <openssl/evp.h>
#include <utility>

using namespace CryptoInternal;

namespace {
    constexpr size_t kKeyLen = 32;
    constexpr size_t kIvLen = 12;
    constexpr size_t kTagLen = 16;
}


CryptoUtils::AeadCipherText CryptoInternal::aesGcmEncryptWithIv(
    const Bytes &key, const Bytes &iv, const Bytes &plainText, const Bytes &aad
)
{
    // ШАГ 0: валидация key и iv (см. «требование 1»). Исключение — CryptoException.
    if (key.size() != kKeyLen) {
        throw CryptoException("Invalid key length");
    }

    if (iv.size() != kIvLen) {
        throw CryptoException("Invalid IV length");
    }
    // ШАГ 1: EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());  + throwIfNull
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    throwIfNull(ctx.get(), "Create EVP_CIPHER_CTX_new");

    // ШАГ 2: инициализация в ДВА этапа:
    //   (а) EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)  — только алгоритм
    throwIfFailed(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "Created (EVP_AES_256_GCM) EV_EncryptInit_ex");
    
    //   (б) EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, kIvLen, nullptr)
    throwIfFailed(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, kIvLen, nullptr), "Created (set aead, ivlen)EVP_CIPHER_CTX_ctrl failed");
    
    //   (в) EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())  — ключ и IV
    throwIfFailed(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()), "Created: (init key and IV) EVP_EncryptInit_ex failed");
    //   ВОПРОС: почему IV нельзя передать сразу в (а)? Подумай, зачем (б) стоит между ними.

    // ШАГ 3: AAD — EVP_EncryptUpdate с out == nullptr.
    //   Это не опечатка: так OpenSSL отличает AAD от данных.
    //   ВОПРОС: что вернёт aad.data(), если вектор пустой? Как ты обошёл это в hkdf?

    
    // alternative way (for small aad)
    // Need to write for large aad code. At now, i coded only for small aad. (To improve)
    if (!aad.empty())
    {
        int aadWritten = 0;
        throwIfFailed(EVP_EncryptUpdate(ctx.get(), nullptr, &aadWritten, aad.data(), static_cast<int>(aad.size())), "EVP_EncryptUpdate failed");
    }
    
    
    // ШАГ 4: шифрование. Размер выходного буфера = ? (см. «размер шифротекста»)
    //   ВОПРОС: какого типа длина во входном параметре EVP_EncryptUpdate?
    //   Что произойдёт при plaintext.size() > INT_MAX (а у нас будут файлы)? Проверь.
    Bytes cipherText(plainText.size() + EVP_MAX_BLOCK_LENGTH); // +16 для AES-GCM, но безопаснее выделить больше
    int written = 0;
    if(!plainText.empty())
    {
        throwIfFailed(EVP_EncryptUpdate(ctx.get(), cipherText.data(), &written, plainText.data(), static_cast<int>(plainText.size())), "EVP_EncryptUpdate failed");
    }
    
    // ШАГ 5: EVP_EncryptFinal_ex — обязательно, даже если пишет 0 байт.
    // throwIfFailed(EVP_EncryptFinal_ex(ctx.get(), cipherText.data(), nullptr), "EVP_EncryptFinal_ex failed");
    int finalWritten = 0;   // сколько байт записано в cipherText.data() после Final
    throwIfFailed(EVP_EncryptFinal_ex(ctx.get(), cipherText.data() + written, &finalWritten), "EVP_EncryptFinal_ex failed"); // Final записывает в cipherText.data() начиная с written, поэтому +written
    cipherText.resize(static_cast<size_t> (written + finalWritten)); // обрезаем лишние байты, если они были выделены

    // ШАГ 6: тег — EVP_CTRL_AEAD_GET_TAG, kTagLen байт. Только ПОСЛЕ Final.
    Bytes tag(kTagLen); // 16 байт для AES-GCM
    throwIfFailed(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, kTagLen, tag.data()), "EVP_CIPHER_CTX_ctrl failed"); 
    return CryptoUtils::AeadCipherText{iv, std::move(cipherText), std::move(tag)}; // std::move — чтобы не копировать, а переместить вектор
}

// ШАГ 7: возвращаем AeadCipherText{iv, cipherText, tag}.
CryptoUtils::AeadCipherText CryptoUtils::aesGcmEncrypt(const Bytes &key, const Bytes &plainText, const Bytes &aad)
{
    // 1) iv = secureRandomBytes(kIvLen)
    // 2) вызываем внутреннюю функцию aesGcmEncryptWithIv с этим iv
    Bytes iv = secureRandomBytes(kIvLen);
    return aesGcmEncryptWithIv(key, iv, plainText, aad);
}

Bytes CryptoUtils::aesGcmDecrypt(const Bytes &key, const AeadCipherText &cipherText, const Bytes &aad)
{
    
    // ШАГ 0: валидация key, iv И ТЕГА (см. «требования 1 и 2»)
    if (key.size() != kKeyLen)
    {
        throw CryptoException ("Invalid key length");
    }
    else if (cipherText.iv.size() != kIvLen)
    {
        throw CryptoException ("Invalid IV Length");
    }
    else if (cipherText.tag.size() != kTagLen)
    {
        throw CryptoException ("Invalid tag length");
    }

    // ШАГ 1-3: как у шифрования (контекст, двухэтапный init, AAD), но Decrypt*
    EvpCipherCtxPtr ctx (EVP_CIPHER_CTX_new());
    throwIfNull(ctx.get(), "EVP_CIPHER_CTX_new failed");

    throwIfFailed(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "EVP_DecryptInit_ex failed");
    throwIfFailed(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, kIvLen, nullptr), "EVP_CIPHER_CTX_ctrl failed");
    throwIfFailed(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), cipherText.iv.data()), "EVP_DecryptInit_ex failed");

    if (!aad.empty())
    {
        int aadWritten = 0;
        throwIfFailed(EVP_DecryptUpdate(ctx.get(), nullptr, &aadWritten, aad.data(), static_cast<int>(aad.size())), "EVP_DecryptUpdate failed");
    }
    // ШАГ 4: EVP_DecryptUpdate -> буфер plaintext
    Bytes plainText(cipherText.cipherText.size() + EVP_MAX_BLOCK_LENGTH); // +16 для AES-GCM, но безопаснее выделить больше
    WipeOut guard(plainText); // чтобы очистить буфер при выходе из функции (throw)
    int written = 0;
    
    if (!cipherText.cipherText.empty())
    {
        throwIfFailed(EVP_DecryptUpdate(ctx.get(), plainText.data(), &written, cipherText.cipherText.data(), static_cast<int>(cipherText.cipherText.size())), "EVP_DecryptUpdate failed");
    }
    // ШАГ 5: ПЕРЕД Final установить тег: EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kTagLen, ...)
    //   ВНИМАНИЕ на константность: ctrl принимает void*, а у тебя const Bytes.
    //   Ты уже решал похожее в hkdf — чем это оправдано здесь?
    throwIfFailed(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, kTagLen, const_cast<uint8_t*>(cipherText.tag.data())), "EVP_CIPHER_CTX_ctrl failed");
    
    // ШАГ 6: EVP_DecryptFinal_ex. Результат <= 0 означает «тег не сошёлся».
    //   В этом случае: не отдавай plaintext, а бросай исключение.
    //   ВОПРОС: что лежит в буфере plaintext в этот момент? Что с ним нужно сделать до throw?
    //   И подумай: нужен ли отдельный тип исключения (наследник CryptoException),
    //   чтобы вызывающий код отличал «подделка» от «ошибка программы»?

    int finalWritten = 0;
    int ret = EVP_DecryptFinal_ex(ctx.get(), plainText.data() + written, &finalWritten);
    if (ret <= 0)
    {
        
        throw CryptoException ("Decryption failed: tag mismatch or corrupted ciphertext");
    }
    plainText.resize(static_cast<size_t>(written + finalWritten)); // обрезаем лишние байты, если они были выделены
    guard.disarm();
    return plainText;
}

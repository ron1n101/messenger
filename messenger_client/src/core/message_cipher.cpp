#include "core/message_cipher.h"
#include "core/signal_exception.h"
#include "core/signal_ptr.h"
#include "protocol.h"
#include "session_cipher.h"
#include <memory>

namespace {
    struct SessionCipherFree
    {
        void operator () (session_cipher *cipher) const
        {
            session_cipher_free(cipher);
        }
    };

    using SessionCipherPtr = std::unique_ptr<session_cipher, SessionCipherFree>;
    using SecretBufferPtr = std::unique_ptr<signal_buffer, decltype(&signal_buffer_bzero_free)>;

    // адрес собеседника
    signal_protocol_address makeAddress(const std::string &name, int deviceId)
    {
        if (name.empty())
        {
            throw CryptoException ("MessageCipher: contact name is empty");
        }
        signal_protocol_address address {};
        address.name = name.c_str();
        address.device_id = deviceId;
        address.name_len = name.size();
        return address;
    }

    // создаём Session_Cipher для собеседника
    SessionCipherPtr makeCipher(signal_protocol_store_context *stores, const signal_protocol_address *address, signal_context *context)
    {
        session_cipher *raw = nullptr;
        int result = session_cipher_create(&raw, stores, address, context);
        if (result < 0)
        {
            throw SignalException ("session_cipher_create failed", result);
        }
        return SessionCipherPtr(raw);
    }
}


MessageCipher::MessageCipher(signal_context *context, ProtocolStoreContext &stores) : m_context(context), m_stores(stores)
{
    if (m_context == nullptr)
    {
        throw CryptoException ("MessageCipher: context is null");
    }
}

EncryptedMessage MessageCipher::encrypt (const std::string &contactName, int deviceId, const Bytes &plainText)
{
    // адрес
    const signal_protocol_address address = makeAddress(contactName, deviceId);
    
    // без сессии нельзя шифровать - выдаём ошибку
    if (!m_stores.hasSession(contactName, deviceId))
    {
        throw SignalException("encrypt: no session", SG_ERR_NO_SESSION);
    }

    // сам шифровальщик
    SessionCipherPtr cipher = makeCipher (m_stores.get(), &address, m_context);

    // шифруем
    static const uint8_t kEmpty = 0;
    ciphertext_message *raw = nullptr;
    int result = session_cipher_encrypt(cipher.get(), plainText.empty() ? &kEmpty : plainText.data(), plainText.size(), &raw);
    if (result < 0)
    {
        throw SignalException ("session_cipher_encrypt failed", result);
    }

    // зашифрованное сообщение - в обёртку
    SignalPtr<ciphertext_message> message(raw);

    // достаём тип и байты
    EncryptedMessage encrypted;
    encrypted.type = ciphertext_message_get_type(message.get());
    signal_buffer *serialized = ciphertext_message_get_serialized(message.get());
    encrypted.body = Bytes(signal_buffer_data(serialized), signal_buffer_data(serialized) + signal_buffer_len(serialized));

    // возвращаем результат
    return encrypted;
}

Bytes MessageCipher::decrypt (const std::string &contactName, int deviceId, const EncryptedMessage &message)
{
    // адрес и проверка на пустое сообщение
    const signal_protocol_address address = makeAddress(contactName, deviceId);
    if (message.body.empty())
    {
        throw CryptoException ("decrypt: message is empty");
    }

    // шифровальщик (сессии у получателя может не быть, поэтому не проверяет наличие сессии)
    SessionCipherPtr cipher = makeCipher(m_stores.get(), &address, m_context);
    signal_buffer *rawPlain = nullptr;
    int result = 0;

    // разбираем и расшифровуем по двум типам (preKeyMessage, kSignalMessage)
    if (message.type == kPreKeyMessage)
    {
        pre_key_signal_message *raw = nullptr;
        result = pre_key_signal_message_deserialize(&raw, message.body.data(), message.body.size(), m_context);
        if (result < 0)
        {
            throw SignalException ("pre_key_signal_message_deserialize failed", result);
        }
        SignalPtr<pre_key_signal_message> parsed (raw);
        result = session_cipher_decrypt_pre_key_signal_message(cipher.get(), parsed.get(), nullptr, &rawPlain);
    }
    else if(message.type == kSignalMessage)
    {
        signal_message *raw = nullptr;
        result = signal_message_deserialize(&raw, message.body.data(), message.body.size(), m_context);
        if (result < 0)
        {
            throw SignalException ("signal_message_deserialize failed", result);
        }
        SignalPtr<signal_message> parsed (raw);
        result = session_cipher_decrypt_signal_message(cipher.get(), parsed.get(), nullptr, &rawPlain);
    }
    else
    {
        throw CryptoException ("decrypt: unknown message type");
    }


    // обработка ошибки расшифровки
    if (result < 0)
    {
        throw SignalException ("session_cipher_decrypt failed", result);
    }


    // выдаём открытый текст (сначала в обёртку с затиранием, копируем в байты и возвращем)
    SecretBufferPtr plain (rawPlain, signal_buffer_bzero_free);
    const uint8_t *begin = signal_buffer_data(plain.get());
    return Bytes (begin, begin + signal_buffer_len(plain.get()));
}


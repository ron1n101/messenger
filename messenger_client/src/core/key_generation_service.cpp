#include "core/key_generation_service.h"
#include "crypto/crypto_exception.h"
#include "key_helper.h"

#include <chrono>
#include <string>


// обработчик ошибок, свой делитор, дата когда был создан ключ
namespace{

    // обработчик ошибок
    void throwIfSignalError(int result, const char *operation)
    {
        if (result < 0)
        {
            throw CryptoException(std::string(operation) + " failed with code: " + std::to_string(result));
        }
    }


    // делитор
    struct PreKeyListFree
    {
        void operator() (signal_protocol_key_helper_pre_key_list_node *head) const
        {
            signal_protocol_key_helper_key_list_free(head);
        }
    };

    uint64_t nowMilliseconds()
    {
        using namespace std::chrono;
        return static_cast<uint64_t>
        (duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());

    }
}

KeyGenerationService::KeyGenerationService(signal_context *context) : m_context(context)
{
    if (m_context == nullptr)
    {
        throw CryptoException("KeyGenerationService: context is null");
    }
}

SignalPtr<ratchet_identity_key_pair> KeyGenerationService::generateIdentityKeyPair()
{
    ratchet_identity_key_pair *raw = nullptr;
    throwIfSignalError(
        signal_protocol_key_helper_generate_identity_key_pair(&raw, m_context),
        "generate_identity_key_pair");
    return SignalPtr<ratchet_identity_key_pair>(raw);
}

uint32_t KeyGenerationService::generateRegistrationId()
{
    uint32_t registrationId = 0;
    throwIfSignalError(signal_protocol_key_helper_generate_registration_id(&registrationId, 0, m_context), "generate_registration_id");
    return registrationId;
}


SignalPtr<session_signed_pre_key> KeyGenerationService::generateSignedPreKey(
    const ratchet_identity_key_pair *identityKeyPair, uint32_t signedPreKeyId)
{
    if (identityKeyPair == nullptr)
    {
        throw CryptoException("generateSignedPreKey: identity key pair is null");
    }
    session_signed_pre_key *raw = nullptr;
    throwIfSignalError(signal_protocol_key_helper_generate_signed_pre_key(&raw, identityKeyPair, signedPreKeyId, nowMilliseconds(), m_context), "generate_signed_pre_key");

    return SignalPtr<session_signed_pre_key>(raw);
}

std::vector<SignalPtr<session_pre_key>> KeyGenerationService::generatePreKeys(
    uint32_t firstId, unsigned int count)
{
    if (count == 0)
    {
        throw CryptoException ("generateKeys: count must be positive");
    }

    if (firstId < 1 || firstId > kMaxPreKeyId)
    {
        throw CryptoException("generateKeys: firstId out of range");
    }

    // строим связный список
    signal_protocol_key_helper_pre_key_list_node *rawHead = nullptr;
    throwIfSignalError(signal_protocol_key_helper_generate_pre_keys(&rawHead, firstId, count, m_context), "generate_pre_keys");

    // кидаем список во временную обёртку
    std::unique_ptr<signal_protocol_key_helper_pre_key_list_node, PreKeyListFree> head(rawHead);

    // перекидываем ключи сразу в вектор и резервируем место под count
    std::vector<SignalPtr<session_pre_key>> result;
    result.reserve(count);

    for (auto *node = head.get(); node != nullptr; node = signal_protocol_key_helper_key_list_next(node))
    {
        result.push_back(signalRef(signal_protocol_key_helper_key_list_element(node)));
    }
    return result;
}


GeneratedIdentity KeyGenerationService::generateNewIdentity(unsigned int preKeyCount)
{
    GeneratedIdentity identity;
    identity.identityKeyPair = generateIdentityKeyPair();
    identity.registrationId += 1 ;
    identity.signedPreKey = generateSignedPreKey(identity.identityKeyPair.get(), 1);
    identity.oneTimePreKeys = generatePreKeys(1, preKeyCount);
    return identity;
}
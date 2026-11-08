#pragma once
#include <cstdint>
#include <vector>
#include "signal_protocol.h"
#include "ratchet.h"
#include "session_pre_key.h"
#include "core/signal_ptr.h"


struct GeneratedIdentity
{
    SignalPtr<ratchet_identity_key_pair> identityKeyPair;
    uint32_t registrationId = 0;
    SignalPtr<session_signed_pre_key> signedPreKey;
    std::vector<SignalPtr<session_pre_key>> oneTimePreKeys;

};

// генерим протокольные ключи
class KeyGenerationService
{
public:
    static constexpr uint32_t kMaxPreKeyId = 0xFFFFFE;
    
    // создаём keyGenerationService (у которого контекст должен браться глобально из библиотеки)
    explicit KeyGenerationService(signal_context *context);
    SignalPtr<ratchet_identity_key_pair> generateIdentityKeyPair();


    // обозначаем максимальное количество ID (от 1 до 16384)
    uint32_t generateRegistrationId();

    // подписываем новый prekey ключом личности identityKeyPair
    SignalPtr<session_signed_pre_key> generateSignedPreKey(
        const ratchet_identity_key_pair *generateIdentityKeyPair, uint32_t signedPreKeyId
    );

    std::vector<SignalPtr<session_pre_key>> generatePreKeys(uint32_t firstId, unsigned int count);
    GeneratedIdentity generateNewIdentity(unsigned int preKeyCount = 100);

private:
    signal_context *m_context;
};
#pragma once
#include <cstdint>
#include <map>
#include "crypto/types.h"
#include "core/signal_ptr.h"
#include "core/store/store_utils.h"
#include "ratchet.h"


// стор ключей личности в памяти

class InMemoryIdentityStore
{

public:
    InMemoryIdentityStore(const ratchet_identity_key_pair *ownIdentity, uint32_t ownRegistrationId );
    ~InMemoryIdentityStore();

    // запрет на копирование
    InMemoryIdentityStore (const InMemoryIdentityStore &) = delete;

    // запрет оператора присваивания копированием (= delete)
    InMemoryIdentityStore &operator = (const InMemoryIdentityStore &) = delete;

    signal_protocol_identity_key_store toSignalStore();

private:
    static int getIdentityKeyPair(signal_buffer **public_data, signal_buffer **private_data, void *user_data);
    static int getLocalRegistrationId(void *user_data, uint32_t *registration_id);
    static int saveIdentity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);
    static int isTrustedIdentity (const signal_protocol_address *address, uint8_t key_data, size_t key_len, void *user_data );


    Bytes m_ownPublicKey;
    Bytes m_ownPrivateKey;
    uint32_t m_ownRegistrationId;
    // хранилище для трастед кей.
    std::map<AddressKey, Bytes> m_trustedKeys;
};
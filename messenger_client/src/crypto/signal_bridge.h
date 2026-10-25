#pragma once
#include <cstddef>
#include <cstdint>
#include "signal_protocol.h"

namespace SignalBridge
{
    // fill data with random bytes(len - counts)
    int randomFunc(uint8_t *data, size_t len, void *user_data);

    int encryptFunc(signal_buffer **output, int cipher,
    const uint8_t *key, size_t key_len, const uint8_t *iv,
    size_t iv_len, const uint8_t *plainText, size_t plainText_len,
    void *user_data);

    // decrypt cipherText and put the result in *output
    int decryptFunc(signal_buffer **output, int cipher, 
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *cipherText, size_t cipherText_len,
    void *user_data);



    // init, update, final, cleanup
    int hmacInitFunc(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
    int hmacUpdateFunc(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
    int hmacFinalFunc(void *hmac_context, signal_buffer **output, void *user_data);
    void hmacCleanupFunc(void *hmac_context, void *user_data);
}
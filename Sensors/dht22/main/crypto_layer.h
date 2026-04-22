#pragma once
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "kem.h"

#define PACKET_CT_LEN    CRYPTO_CIPHERTEXTBYTES   
#define PACKET_IV_LEN    12
#define PACKET_TAG_LEN   16

typedef struct {
    uint8_t session_key[CRYPTO_BYTES]; 
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    int     ready;
} crypto_session_t;

esp_err_t crypto_session_init(const uint8_t *edge_pk, crypto_session_t *session);

esp_err_t crypto_encrypt(crypto_session_t *session,
                         const uint8_t *plaintext, size_t data_len,
                         uint8_t *out_buf, size_t *out_len);

void crypto_session_clear(crypto_session_t *session);
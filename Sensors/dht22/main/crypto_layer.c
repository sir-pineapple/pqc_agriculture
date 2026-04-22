#include "crypto_layer.h"
#include "psa/crypto.h"
#include "esp_random.h"
#include "esp_log.h"
#include <string.h>

#define TAG "CRYPTO"

esp_err_t crypto_session_init(const uint8_t *edge_pk,
                               crypto_session_t *session) {
    psa_status_t psa_ret = psa_crypto_init();
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)psa_ret);
        return ESP_FAIL;
    }

    int ret = crypto_kem_enc(session->ct,
                             session->session_key,
                             edge_pk);
    if (ret != 0) {
        ESP_LOGE(TAG, "crypto_kem_enc failed: %d", ret);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Raw shared secret (first 8 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, session->session_key, 8);

    uint8_t raw_secret[CRYPTO_BYTES];
    memcpy(raw_secret, session->session_key, CRYPTO_BYTES);

    static const uint8_t salt[] = "agriculture";
    static const uint8_t info[] = "tier1";

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    psa_ret = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF setup failed: %d", (int)psa_ret);
        goto hkdf_fail;
    }

    psa_ret = psa_key_derivation_input_bytes(&op,
                  PSA_KEY_DERIVATION_INPUT_SALT,
                  salt, sizeof(salt) - 1);
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF salt failed: %d", (int)psa_ret);
        goto hkdf_fail;
    }

    psa_ret = psa_key_derivation_input_bytes(&op,
                  PSA_KEY_DERIVATION_INPUT_SECRET,
                  raw_secret, CRYPTO_BYTES);
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF secret failed: %d", (int)psa_ret);
        goto hkdf_fail;
    }

    psa_ret = psa_key_derivation_input_bytes(&op,
                  PSA_KEY_DERIVATION_INPUT_INFO,
                  info, sizeof(info) - 1);
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF info failed: %d", (int)psa_ret);
        goto hkdf_fail;
    }

    psa_ret = psa_key_derivation_output_bytes(&op,
                  session->session_key, 32);
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "HKDF output failed: %d", (int)psa_ret);
    }

hkdf_fail:
    psa_key_derivation_abort(&op);
    memset(raw_secret, 0, CRYPTO_BYTES);
    if (psa_ret != PSA_SUCCESS) return ESP_FAIL;

    session->ready = 1;
    ESP_LOGI(TAG, "Kyber+HKDF session established. Key (first 8 bytes):");
    ESP_LOG_BUFFER_HEX(TAG, session->session_key, 8);
    return ESP_OK;
}

esp_err_t crypto_encrypt(crypto_session_t *session,
                         const uint8_t *plaintext, size_t data_len,
                         uint8_t *out_buf, size_t *out_len) {
    if (!session->ready) return ESP_ERR_INVALID_STATE;

    uint8_t iv[PACKET_IV_LEN];
    esp_fill_random(iv, PACKET_IV_LEN);

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);

    psa_key_id_t key_id;
    psa_status_t psa_ret = psa_import_key(&attrs,
                                          session->session_key, CRYPTO_BYTES,
                                          &key_id);
    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_import_key failed: %d", (int)psa_ret);
        return ESP_FAIL;
    }

    uint8_t *ct_and_tag     = out_buf + PACKET_IV_LEN;
    size_t   ct_and_tag_len = 0;
    size_t   ct_buf_size    = data_len + PACKET_TAG_LEN;

    psa_ret = psa_aead_encrypt(key_id,
                               PSA_ALG_GCM,
                               iv,        PACKET_IV_LEN,
                               NULL,      0,
                               plaintext, data_len,
                               ct_and_tag, ct_buf_size, &ct_and_tag_len);

    psa_destroy_key(key_id);

    if (psa_ret != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_aead_encrypt failed: %d", (int)psa_ret);
        return ESP_FAIL;
    }

    memcpy(out_buf, iv, PACKET_IV_LEN);
    *out_len = PACKET_IV_LEN + ct_and_tag_len;

    return ESP_OK;
}

void crypto_session_clear(crypto_session_t *session) {
    memset(session->session_key, 0, CRYPTO_BYTES);
    memset(session->ct,          0, CRYPTO_CIPHERTEXTBYTES);
    session->ready = 0;
    ESP_LOGI(TAG, "Session key wiped from RAM");
}
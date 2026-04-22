#include "soil_moisture.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_log.h"
 
#define TAG          "SOIL"
#define SOIL_ADC_UNIT    ADC_UNIT_1
#define SOIL_ADC_CHANNEL ADC_CHANNEL_6   // GPIO 34 = ADC1_CH6
 
// Calibration: sensor in air (dry) reads ~4095, in water (wet) reads ~1200
// Adjust these if your sensor differs
#define SOIL_DRY_RAW  4095
#define SOIL_WET_RAW  1200
 
static adc_oneshot_unit_handle_t adc_handle = NULL;
 
static esp_err_t soil_adc_init(void) {
    if (adc_handle != NULL) return ESP_OK; // already initialized
 
    adc_oneshot_unit_init_cfg_t unit_cfg = {
        .unit_id = SOIL_ADC_UNIT,
    };
    esp_err_t ret = adc_oneshot_new_unit(&unit_cfg, &adc_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "ADC unit init failed: %s", esp_err_to_name(ret));
        return ret;
    }
 
    adc_oneshot_chan_cfg_t chan_cfg = {
        .atten    = ADC_ATTEN_DB_12,   // 0–3.3 V range
        .bitwidth = ADC_BITWIDTH_12,   // 12-bit (0–4095)
    };
    ret = adc_oneshot_config_channel(adc_handle, SOIL_ADC_CHANNEL, &chan_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "ADC channel config failed: %s", esp_err_to_name(ret));
        return ret;
    }
 
    return ESP_OK;
}
 
esp_err_t soil_moisture_read(soil_moisture_data_t *out) {
    esp_err_t ret = soil_adc_init();
    if (ret != ESP_OK) return ESP_ERR_INVALID_STATE;
 
    int raw = 0;
    ret = adc_oneshot_read(adc_handle, SOIL_ADC_CHANNEL, &raw);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "ADC read failed: %s", esp_err_to_name(ret));
        return ESP_ERR_INVALID_STATE;
    }
 
    out->raw = (uint16_t)raw;
 
    // Map raw to moisture %: dry (high raw) = 0%, wet (low raw) = 100%
    float pct = ((float)(SOIL_DRY_RAW - raw) / (float)(SOIL_DRY_RAW - SOIL_WET_RAW)) * 100.0f;
    if (pct < 0.0f)   pct = 0.0f;
    if (pct > 100.0f) pct = 100.0f;
    out->moisture_pct = pct;
 
    ESP_LOGI(TAG, "Raw: %d  Moisture: %.1f%%", raw, pct);
    return ESP_OK;
}
#pragma once
#include "esp_err.h"
 
typedef struct {
    uint16_t raw;        // Raw ADC value (0–4095)
    float    moisture_pct; // Mapped moisture percentage (0–100%)
} soil_moisture_data_t;
 
/**
 * Read soil moisture from a resistive sensor on ADC1
 * @param data  Output struct for raw ADC value and moisture percentage
 * @return ESP_OK on success, ESP_ERR_INVALID_STATE on ADC failure
 */
esp_err_t soil_moisture_read(soil_moisture_data_t *data);
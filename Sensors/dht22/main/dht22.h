#pragma once
#include "esp_err.h"
#include "driver/gpio.h"

typedef struct {
    float temperature;  // Celsius
    float humidity;     // %RH
} dht22_data_t;

/**
 * Read temperature and humidity from DHT22
 * @param gpio_pin  GPIO pin connected to DHT22 data line
 * @param data      Output struct for temperature and humidity
 * @return ESP_OK on success, ESP_ERR_TIMEOUT or ESP_ERR_INVALID_CRC on failure
 */
esp_err_t dht22_read(gpio_num_t gpio_pin, dht22_data_t *data);
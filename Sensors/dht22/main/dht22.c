#include "dht22.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rom/ets_sys.h"
#include "esp_log.h"

#define TAG "DHT22"
#define TIMEOUT 100

static esp_err_t wait_level(gpio_num_t pin, int lvl, uint32_t us) {
    uint32_t t = 0;
    while (gpio_get_level(pin) != lvl) {
        if (t++ >= us) return ESP_ERR_TIMEOUT;
        ets_delay_us(1);
    }
    return ESP_OK;
}

esp_err_t dht22_read(gpio_num_t pin, dht22_data_t *out) {
    uint8_t bits[40] = {0};
    uint8_t bytes[5] = {0};

    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin, 0);
    ets_delay_us(1100);
    gpio_set_level(pin, 1);
    ets_delay_us(30);
    gpio_set_direction(pin, GPIO_MODE_INPUT);

    if (wait_level(pin, 0, TIMEOUT) != ESP_OK) return ESP_ERR_TIMEOUT;
    if (wait_level(pin, 1, TIMEOUT) != ESP_OK) return ESP_ERR_TIMEOUT;
    if (wait_level(pin, 0, TIMEOUT) != ESP_OK) return ESP_ERR_TIMEOUT;

    for (int i = 0; i < 40; i++) {
        if (wait_level(pin, 1, TIMEOUT) != ESP_OK) return ESP_ERR_TIMEOUT;
        uint32_t hi = 0;
        while (gpio_get_level(pin) == 1) {
            if (hi++ >= TIMEOUT) return ESP_ERR_TIMEOUT;
            ets_delay_us(1);
        }
        bits[i] = (hi > 40) ? 1 : 0;
    }

    for (int i = 0; i < 40; i++) {
        bytes[i / 8] <<= 1;
        bytes[i / 8] |= bits[i];
    }

    if ((uint8_t)(bytes[0] + bytes[1] + bytes[2] + bytes[3]) != bytes[4]) {
        ESP_LOGE(TAG, "Checksum failed");
        return ESP_ERR_INVALID_CRC;
    }

    out->humidity    = ((bytes[0] << 8) | bytes[1]) / 10.0f;
    int16_t raw_temp = ((bytes[2] & 0x7F) << 8) | bytes[3];
    if (bytes[2] & 0x80) raw_temp = -raw_temp;
    out->temperature = raw_temp / 10.0f;

    return ESP_OK;
}
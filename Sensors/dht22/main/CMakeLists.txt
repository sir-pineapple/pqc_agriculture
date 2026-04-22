idf_component_register(
    SRCS
        "main.c"
        "dht22.c"
        "crypto_layer.c"
    INCLUDE_DIRS "."
    REQUIRES
        kem
        mbedtls
        esp_timer
        esp_hw_support
        esp_driver_gpio
        esp_wifi
        esp_event
        esp_netif
        nvs_flash
        lwip
)
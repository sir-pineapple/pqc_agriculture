#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "dht22.h"
#include "crypto_layer.h"

#define TAG           "MAIN"
#define DHT22_PIN     GPIO_NUM_4

#define WIFI_SSID     [WIFI_SSID]
#define WIFI_PASS     [WIFI_PASSWORD]
#define EDGE_IP       [EDGE_IP]
#define EDGE_PORT     4000

#define MSG_PK        0x00
#define MSG_HANDSHAKE 0x01
#define MSG_HANDSHAKE_ACK 0x02
#define MSG_DATA      0x03

typedef struct __attribute__((packed)) {
    float    temperature;
    float    humidity;
    uint32_t timestamp_ms;
} sensor_payload_t;

static crypto_session_t  session;
static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi lost, reconnecting...");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "IP: " IPSTR, IP2STR(&e->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init(void) {
    wifi_event_group = xEventGroupCreate();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                &wifi_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                &wifi_event_handler, NULL);

    wifi_config_t wifi_cfg = {};
    strncpy((char *)wifi_cfg.sta.ssid,     WIFI_SSID, 32);
    strncpy((char *)wifi_cfg.sta.password, WIFI_PASS, 64);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg);
    esp_wifi_start();

    ESP_LOGI(TAG, "Connecting to %s ...", WIFI_SSID);
    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT,
                        false, true, portMAX_DELAY);
}

static int tcp_send_all(int sock, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n < 0) return -1;
        sent += n;
    }
    return 0;
}

static int tcp_recv_all(int sock, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = recv(sock, buf + got, len - got, MSG_WAITALL);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

void kyber_sensor_task(void *arg) {
    ESP_LOGI(TAG, "=== DHT22 + Kyber + WiFi ===");
    
    while (1) {
        int sock = -1;
        struct sockaddr_in dest = {
            .sin_family = AF_INET,
            .sin_port   = htons(EDGE_PORT),
        };
        inet_pton(AF_INET, EDGE_IP, &dest.sin_addr);

        ESP_LOGI(TAG, "Connecting to Pi %s:%d ...", EDGE_IP, EDGE_PORT);
        while (1) {
            sock = socket(AF_INET, SOCK_STREAM, 0);
            if (connect(sock, (struct sockaddr *)&dest, sizeof(dest)) == 0) break;
            ESP_LOGW(TAG, "Retry in 3s...");
            close(sock);
            vTaskDelay(pdMS_TO_TICKS(3000));
        }
        ESP_LOGI(TAG, "Connected to Pi!");

        uint8_t edge_pk[CRYPTO_PUBLICKEYBYTES];
        if (tcp_recv_all(sock, edge_pk, CRYPTO_PUBLICKEYBYTES) < 0) {
            ESP_LOGE(TAG, "Failed to receive public key");
            close(sock);
            continue;
        }
        ESP_LOGI(TAG, "Public key received from Pi");

        if (crypto_session_init(edge_pk, &session) != ESP_OK) {
            ESP_LOGE(TAG, "KEM failed");
            close(sock);
            continue;
        }
        ESP_LOGI(TAG, "Session key established");

        if (tcp_send_all(sock, session.ct, CRYPTO_CIPHERTEXTBYTES) < 0) {
            ESP_LOGE(TAG, "Failed to send ciphertext");
            close(sock);
            continue;
        }

        uint8_t ack = 0;
        tcp_recv_all(sock, &ack, 1);
        if (ack != MSG_HANDSHAKE_ACK) {
            ESP_LOGE(TAG, "Bad ACK");
            close(sock);
            continue;
        }
        ESP_LOGI(TAG, "Handshake complete — streaming data");

        uint32_t seq = 0;
        while (1) {
            dht22_data_t     reading;
            sensor_payload_t payload;

            esp_err_t ret = dht22_read(DHT22_PIN, &reading);
            if (ret != ESP_OK) {
                ESP_LOGW(TAG, "DHT22 read failed, skipping");
                vTaskDelay(pdMS_TO_TICKS(2500));
                continue;
            }

            payload.temperature  = reading.temperature;
            payload.humidity     = reading.humidity;
            payload.timestamp_ms = (uint32_t)(esp_timer_get_time() / 1000);

            ESP_LOGI(TAG, "Temp: %.1f C  Humidity: %.1f%%",
                     reading.temperature, reading.humidity);

            uint8_t enc_buf[PACKET_IV_LEN + sizeof(payload) + PACKET_TAG_LEN];
            size_t  enc_len = 0;
            if (crypto_encrypt(&session,
                               (uint8_t *)&payload, sizeof(payload),
                               enc_buf, &enc_len) != ESP_OK) {
                ESP_LOGE(TAG, "Encryption failed");
                break;
            }

            uint16_t pkt_len = (uint16_t)enc_len;
            uint8_t  hdr[7];
            hdr[0] = MSG_DATA;
            memcpy(hdr + 1, &seq,     4);
            memcpy(hdr + 5, &pkt_len, 2);

            if (tcp_send_all(sock, hdr,     sizeof(hdr)) < 0 ||
                tcp_send_all(sock, enc_buf, enc_len)     < 0) {
                ESP_LOGW(TAG, "Send failed — reconnecting");
                break;
            }

            seq++;
            vTaskDelay(pdMS_TO_TICKS(2500));
        }

        close(sock);
        ESP_LOGW(TAG, "Disconnected — reconnecting...");
        vTaskDelay(pdMS_TO_TICKS(2500));
    }
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    wifi_init();
    xTaskCreate(kyber_sensor_task, "kyber_task", 32768, NULL, 5, NULL);
}
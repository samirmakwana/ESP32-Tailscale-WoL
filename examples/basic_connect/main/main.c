/**
 * @file main.c
 * @brief MicroLink Basic Connect Example
 *
 * This example demonstrates the minimal code needed to connect
 * an ESP32 to a Tailscale network using MicroLink.
 *
 * After flashing, test with: tailscale ping <device-name>
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "microlink.h"

static const char *TAG = "example";

/* ============================================================================
 * Configuration - CHANGE THESE VALUES
 * ========================================================================== */

// WiFi credentials
#define WIFI_SSID      "YOUR_WIFI_SSID"
#define WIFI_PASSWORD  "YOUR_WIFI_PASSWORD"

// Tailscale auth key (get from https://login.tailscale.com/admin/settings/keys)
#define TAILSCALE_AUTH_KEY  "tskey-auth-XXXXXXXX"

// Device name (will appear in Tailscale admin console)
#define DEVICE_NAME    "esp32-microlink"

/* ============================================================================
 * WiFi Connection
 * ========================================================================== */

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int s_retry_num = 0;
#define WIFI_MAX_RETRY 10

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retrying WiFi connection... (%d/%d)", s_retry_num, WIFI_MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "WiFi connected! IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                    ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                    IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to WiFi...");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to SSID: %s", WIFI_SSID);
        return ESP_OK;
    } else {
        ESP_LOGE(TAG, "Failed to connect to WiFi");
        return ESP_FAIL;
    }
}

/* ============================================================================
 * MicroLink Callbacks (optional)
 * ========================================================================== */

static void on_connected(void) {
    ESP_LOGI(TAG, "*** TAILSCALE CONNECTED ***");
}

static void on_disconnected(void) {
    ESP_LOGW(TAG, "Tailscale disconnected");
}

static void on_peer_added(const microlink_peer_t *peer) {
    char ip_str[16];
    ESP_LOGI(TAG, "Peer added: %s (%s)",
             peer->hostname,
             microlink_vpn_ip_to_str(peer->vpn_ip, ip_str));
}

static void on_state_change(microlink_state_t old_state, microlink_state_t new_state) {
    ESP_LOGI(TAG, "State: %s -> %s",
             microlink_state_to_str(old_state),
             microlink_state_to_str(new_state));
}

/* ============================================================================
 * Main Application
 * ========================================================================== */

void app_main(void) {
    ESP_LOGI(TAG, "=== MicroLink Basic Connect Example ===");
    ESP_LOGI(TAG, "MicroLink version: %s", MICROLINK_VERSION);

    // Initialize NVS (required for WiFi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Connect to WiFi
    if (wifi_init_sta() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi connection failed. Restarting...");
        vTaskDelay(pdMS_TO_TICKS(3000));
        esp_restart();
    }

    // Configure MicroLink
    microlink_config_t config;
    microlink_get_default_config(&config);

    config.auth_key = TAILSCALE_AUTH_KEY;
    config.device_name = DEVICE_NAME;
    config.enable_derp = true;
    config.enable_disco = true;
    config.enable_stun = true;

    // Optional callbacks
    config.on_connected = on_connected;
    config.on_disconnected = on_disconnected;
    config.on_peer_added = on_peer_added;
    config.on_state_change = on_state_change;

    // Initialize MicroLink
    ESP_LOGI(TAG, "Initializing MicroLink...");
    microlink_t *ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "Failed to initialize MicroLink");
        return;
    }

    // Start connection
    ESP_LOGI(TAG, "Connecting to Tailscale...");
    ret = microlink_connect(ml);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start connection: %s", esp_err_to_name(ret));
        microlink_deinit(ml);
        return;
    }

    // Main loop
    char ip_str[16];
    bool was_connected = false;

    while (1) {
        // Update MicroLink state machine
        microlink_update(ml);

        // Check connection status
        bool is_connected = microlink_is_connected(ml);

        if (is_connected && !was_connected) {
            // Just connected - print VPN IP
            uint32_t vpn_ip = microlink_get_vpn_ip(ml);
            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "===================================");
            ESP_LOGI(TAG, "  VPN IP: %s", microlink_vpn_ip_to_str(vpn_ip, ip_str));
            ESP_LOGI(TAG, "  Test:   tailscale ping %s", DEVICE_NAME);
            ESP_LOGI(TAG, "===================================");
            ESP_LOGI(TAG, "");

            // Print peer list
            const microlink_peer_t *peers;
            uint8_t peer_count;
            if (microlink_get_peers(ml, &peers, &peer_count) == ESP_OK) {
                ESP_LOGI(TAG, "Peers (%d):", peer_count);
                for (int i = 0; i < peer_count; i++) {
                    ESP_LOGI(TAG, "  - %s (%s)",
                             peers[i].hostname,
                             microlink_vpn_ip_to_str(peers[i].vpn_ip, ip_str));
                }
            }
        }

        was_connected = is_connected;

        // Small delay to prevent busy-looping
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

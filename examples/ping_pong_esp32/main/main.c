/**
 * @file main.c
 * @brief MicroLink Ping Pong Example - ESP32 (no PSRAM) version
 *
 * This example demonstrates MicroLink running on a standard ESP32 without PSRAM.
 * It includes heap monitoring to track memory usage.
 *
 * Tested on: HiLetgo ESP-32S, ESP32-WROOM-32D, ESP32-DevKitC
 *
 * Test with: tailscale ping <device-name>
 *
 * ============================================================================
 * MEMORY CONSTRAINTS - READ THIS BEFORE ADDING FEATURES
 * ============================================================================
 *
 * Standard ESP32 has ~267KB SRAM total. With MicroLink running, you have
 * approximately 9-15KB of free heap remaining. This is enough for:
 *
 *   WORKS WELL:
 *   - GPIO control (relays, LEDs, buttons)
 *   - I2C/SPI sensors (temperature, humidity, pressure, etc.)
 *   - ADC readings (voltage, current monitoring)
 *   - Simple UART communication
 *   - PWM control (motors, dimmers)
 *   - Small JSON payloads (<1KB)
 *
 *   MARGINAL (needs careful tuning):
 *   - Small OLED displays (SSD1306 128x64 = 1KB framebuffer)
 *   - SD card with small buffers
 *
 *   WON'T FIT:
 *   - LCD/TFT displays (need 50-150KB+ framebuffer)
 *   - Camera modules (need 100KB+)
 *   - Audio/I2S (need large DMA buffers)
 *   - BLE + WiFi simultaneously
 *   - LVGL or other graphics libraries
 *
 * For memory-intensive applications, use ESP32-S3 with PSRAM instead.
 * See examples/ping_pong/ for the PSRAM version.
 *
 * To gain more headroom on basic ESP32:
 *   - Reduce CONFIG_MICROLINK_COORD_BUFFER_SIZE_KB to 16 (saves 8KB)
 *   - Reduce CONFIG_MICROLINK_MAX_PEERS to 4 (saves ~800B)
 *   - Use CONFIG_COMPILER_OPTIMIZATION_SIZE=y
 * ============================================================================
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
#include "esp_timer.h"
#include "esp_heap_caps.h"

#include "microlink.h"

static const char *TAG = "ping_pong_esp32";

/* ============================================================================
 * Configuration - CHANGE THESE VALUES
 * ========================================================================== */

#define WIFI_SSID          "YOUR_WIFI_SSID"
#define WIFI_PASSWORD      "YOUR_WIFI_PASSWORD"
#define TAILSCALE_AUTH_KEY "tskey-auth-xxxxx"
#define DEVICE_NAME        "esp32-basic"

/* ============================================================================
 * Global State
 * ========================================================================== */

static microlink_t *g_microlink = NULL;
static uint32_t g_ping_count = 0;
static uint32_t g_pong_count = 0;

/* ============================================================================
 * Memory Monitoring (important for non-PSRAM ESP32)
 * ========================================================================== */

static void print_heap_info(const char *label) {
    ESP_LOGI(TAG, "[%s] Free heap: %lu bytes, Min free: %lu bytes",
             label,
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)esp_get_minimum_free_heap_size());
}

/* ============================================================================
 * WiFi Connection (same as basic_connect)
 * ========================================================================== */

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGI(TAG, "Retrying WiFi...");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "WiFi connected: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t wifi_init(void) {
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    return ESP_OK;
}

/* ============================================================================
 * Status Display Task
 * ========================================================================== */

static void status_task(void *pvParameters) {
    char ip_str[16];
    uint32_t last_ping_count = 0;

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));  // Update every 10 seconds (longer interval to save CPU)

        if (!g_microlink || !microlink_is_connected(g_microlink)) {
            continue;
        }

        // Print heap info periodically
        print_heap_info("STATUS");

        // Check if we received new pings
        if (g_ping_count != last_ping_count) {
            ESP_LOGI(TAG, "DISCO Activity: %lu pings, %lu pongs",
                     (unsigned long)g_ping_count, (unsigned long)g_pong_count);
            last_ping_count = g_ping_count;
        }

        // Get and display peer latencies
        const microlink_peer_t *peers;
        uint8_t peer_count;
        if (microlink_get_peers(g_microlink, &peers, &peer_count) == ESP_OK && peer_count > 0) {
            ESP_LOGI(TAG, "--- Peer Status ---");
            for (int i = 0; i < peer_count; i++) {
                const microlink_peer_t *p = &peers[i];
                uint32_t latency = microlink_get_peer_latency(g_microlink, p->vpn_ip);

                ESP_LOGI(TAG, "  %s (%s): %lums %s",
                         p->hostname,
                         microlink_vpn_ip_to_str(p->vpn_ip, ip_str),
                         (unsigned long)(latency == UINT32_MAX ? 0 : latency),
                         p->using_derp ? "[DERP]" : "[direct]");
            }
        }

        // Get statistics
        microlink_stats_t stats;
        if (microlink_get_stats(g_microlink, &stats) == ESP_OK) {
            ESP_LOGI(TAG, "Stats: TX=%lu RX=%lu DERP=%lu",
                     (unsigned long)stats.packets_sent,
                     (unsigned long)stats.packets_received,
                     (unsigned long)stats.derp_packets_relayed);
        }
    }
}

/* ============================================================================
 * Main Application
 * ========================================================================== */

void app_main(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "  MicroLink Ping Pong - ESP32 (no PSRAM)");
    ESP_LOGI(TAG, "  Version: %s", MICROLINK_VERSION);
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "");

    print_heap_info("BOOT");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    print_heap_info("NVS");

    // Connect to WiFi
    ESP_LOGI(TAG, "Connecting to WiFi...");
    if (wifi_init() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi failed");
        return;
    }

    print_heap_info("WIFI");

    // Configure MicroLink with reduced peer count for memory optimization
    microlink_config_t config;
    microlink_get_default_config(&config);

    config.auth_key = TAILSCALE_AUTH_KEY;
    config.device_name = DEVICE_NAME;
    config.enable_derp = true;
    config.enable_disco = true;
    config.enable_stun = true;
    config.max_peers = 8;  // Reduced from 16 to save memory on non-PSRAM ESP32

    // Initialize
    ESP_LOGI(TAG, "Initializing MicroLink...");
    g_microlink = microlink_init(&config);
    if (!g_microlink) {
        ESP_LOGE(TAG, "MicroLink init failed - likely out of memory!");
        print_heap_info("FAIL");
        return;
    }

    print_heap_info("MICROLINK_INIT");

    // Connect
    ESP_LOGI(TAG, "Connecting to Tailscale...");
    microlink_connect(g_microlink);

    // Start status display task with smaller stack
    xTaskCreate(status_task, "status", 3072, NULL, 5, NULL);

    // Main loop
    char ip_str[16];
    bool shown_ready = false;

    while (1) {
        microlink_update(g_microlink);

        if (microlink_is_connected(g_microlink) && !shown_ready) {
            print_heap_info("CONNECTED");
            ESP_LOGI(TAG, "");
            ESP_LOGI(TAG, "************************************");
            ESP_LOGI(TAG, "*  READY FOR PING!                 *");
            ESP_LOGI(TAG, "*                                  *");
            ESP_LOGI(TAG, "*  VPN IP: %-20s  *",
                     microlink_vpn_ip_to_str(microlink_get_vpn_ip(g_microlink), ip_str));
            ESP_LOGI(TAG, "*                                  *");
            ESP_LOGI(TAG, "*  Test:  tailscale ping %s", DEVICE_NAME);
            ESP_LOGI(TAG, "*                                  *");
            ESP_LOGI(TAG, "************************************");
            ESP_LOGI(TAG, "");
            shown_ready = true;
        }

        vTaskDelay(pdMS_TO_TICKS(50));  // 50ms update interval
    }
}

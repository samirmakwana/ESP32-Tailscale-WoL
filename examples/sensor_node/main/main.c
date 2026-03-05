/**
 * @file main.c
 * @brief MicroLink Sensor Node Example
 *
 * This example demonstrates a practical IoT use case: sending sensor data
 * over the Tailscale VPN to a server on your tailnet.
 *
 * Features:
 * - Reads temperature/humidity (simulated - replace with real sensor)
 * - Sends JSON data over UDP to a server on the tailnet
 * - Receives commands from the server
 * - Shows how to use microlink_send() and microlink_receive()
 *
 * Server-side example (Python):
 *   import socket
 *   sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 *   sock.bind(('0.0.0.0', 5000))
 *   while True:
 *       data, addr = sock.recvfrom(1024)
 *       print(f"From {addr}: {data.decode()}")
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
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
#include "esp_random.h"

#include "microlink.h"

static const char *TAG = "sensor_node";

/* ============================================================================
 * Configuration - CHANGE THESE VALUES
 * ========================================================================== */

// WiFi credentials
#define WIFI_SSID          "YOUR_WIFI_SSID"
#define WIFI_PASSWORD      "YOUR_WIFI_PASSWORD"

// Tailscale auth key (get from https://login.tailscale.com/admin/settings/keys)
#define TAILSCALE_AUTH_KEY "tskey-auth-XXXXXXXX"

// Device name (will appear in Tailscale admin console)
#define DEVICE_NAME        "esp32-sensor"

// Server configuration - set to the VPN IP of your server on the tailnet
// Find this with: tailscale ip -4 <server-name>
#define SERVER_VPN_IP      "100.x.x.x"  // CHANGE THIS!
#define SERVER_PORT        5000

// Sensor reporting interval (milliseconds)
#define REPORT_INTERVAL_MS 10000  // 10 seconds

/* ============================================================================
 * Simulated Sensor (replace with real sensor code)
 * ========================================================================== */

typedef struct {
    float temperature;  // Celsius
    float humidity;     // Percent
    float battery;      // Voltage
    uint32_t uptime;    // Seconds
} sensor_data_t;

static void read_sensors(sensor_data_t *data) {
    // Simulated sensor readings - replace with real sensor code!
    // Example: DHT22, BME280, etc.

    static float base_temp = 22.0f;
    static float base_humidity = 45.0f;

    // Add some random variation to simulate real readings
    data->temperature = base_temp + ((esp_random() % 100) - 50) / 50.0f;
    data->humidity = base_humidity + ((esp_random() % 100) - 50) / 10.0f;
    data->battery = 3.3f + (esp_random() % 100) / 500.0f;
    data->uptime = esp_timer_get_time() / 1000000;  // Seconds since boot

    // Clamp values
    if (data->humidity < 0) data->humidity = 0;
    if (data->humidity > 100) data->humidity = 100;
}

/* ============================================================================
 * WiFi Connection
 * ========================================================================== */

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW(TAG, "WiFi disconnected, reconnecting...");
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
 * Helper: Parse VPN IP string to uint32_t
 * ========================================================================== */

static uint32_t parse_vpn_ip(const char *ip_str) {
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        return (a << 24) | (b << 16) | (c << 8) | d;
    }
    return 0;
}

/* ============================================================================
 * Sensor Reporting Task
 * ========================================================================== */

static microlink_t *g_microlink = NULL;
static uint32_t g_server_ip = 0;

static void sensor_task(void *pvParameters) {
    char json_buffer[256];
    sensor_data_t data;
    uint32_t report_count = 0;

    // Wait for connection
    while (!microlink_is_connected(g_microlink)) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Sensor task started, reporting every %d ms", REPORT_INTERVAL_MS);

    while (1) {
        // Read sensors
        read_sensors(&data);

        // Format as JSON
        int json_len = snprintf(json_buffer, sizeof(json_buffer),
            "{"
            "\"device\":\"%s\","
            "\"temp\":%.1f,"
            "\"humidity\":%.1f,"
            "\"battery\":%.2f,"
            "\"uptime\":%lu,"
            "\"seq\":%lu"
            "}",
            DEVICE_NAME,
            data.temperature,
            data.humidity,
            data.battery,
            (unsigned long)data.uptime,
            (unsigned long)report_count++
        );

        // Send to server
        if (g_server_ip != 0) {
            esp_err_t ret = microlink_send(g_microlink, g_server_ip,
                                          (uint8_t *)json_buffer, json_len);
            if (ret == ESP_OK) {
                ESP_LOGI(TAG, "Sent: %s", json_buffer);
            } else {
                ESP_LOGW(TAG, "Send failed: %s", esp_err_to_name(ret));
            }
        }

        vTaskDelay(pdMS_TO_TICKS(REPORT_INTERVAL_MS));
    }
}

/* ============================================================================
 * Command Receiver Task
 * ========================================================================== */

static void receiver_task(void *pvParameters) {
    uint8_t rx_buffer[512];
    size_t rx_len;
    uint32_t src_ip;
    char ip_str[16];

    // Wait for connection
    while (!microlink_is_connected(g_microlink)) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Receiver task started, listening for commands...");

    while (1) {
        rx_len = sizeof(rx_buffer) - 1;  // Leave room for null terminator

        esp_err_t ret = microlink_receive(g_microlink, &src_ip, rx_buffer, &rx_len);

        if (ret == ESP_OK && rx_len > 0) {
            rx_buffer[rx_len] = '\0';  // Null terminate

            ESP_LOGI(TAG, "Received from %s: %s",
                     microlink_vpn_ip_to_str(src_ip, ip_str),
                     (char *)rx_buffer);

            // Process commands
            if (strstr((char *)rx_buffer, "\"cmd\":\"status\"")) {
                // Respond with status
                char response[128];
                int len = snprintf(response, sizeof(response),
                    "{\"status\":\"ok\",\"device\":\"%s\",\"free_heap\":%lu}",
                    DEVICE_NAME, (unsigned long)esp_get_free_heap_size());

                microlink_send(g_microlink, src_ip, (uint8_t *)response, len);
                ESP_LOGI(TAG, "Sent status response");
            }
            else if (strstr((char *)rx_buffer, "\"cmd\":\"reboot\"")) {
                ESP_LOGW(TAG, "Reboot command received!");
                vTaskDelay(pdMS_TO_TICKS(1000));
                esp_restart();
            }
        }

        vTaskDelay(pdMS_TO_TICKS(100));  // Check every 100ms
    }
}

/* ============================================================================
 * Main Application
 * ========================================================================== */

void app_main(void) {
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  MicroLink Sensor Node Example");
    ESP_LOGI(TAG, "  Version: %s", MICROLINK_VERSION);
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "");

    // Parse server IP
    g_server_ip = parse_vpn_ip(SERVER_VPN_IP);
    if (g_server_ip == 0) {
        ESP_LOGE(TAG, "Invalid SERVER_VPN_IP: %s", SERVER_VPN_IP);
        ESP_LOGE(TAG, "Please set this to your server's Tailscale IP!");
        return;
    }

    char ip_str[16];
    ESP_LOGI(TAG, "Target server: %s:%d",
             microlink_vpn_ip_to_str(g_server_ip, ip_str), SERVER_PORT);

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Connect to WiFi
    ESP_LOGI(TAG, "Connecting to WiFi...");
    if (wifi_init() != ESP_OK) {
        ESP_LOGE(TAG, "WiFi failed");
        return;
    }

    // Configure MicroLink
    microlink_config_t config;
    microlink_get_default_config(&config);

    config.auth_key = TAILSCALE_AUTH_KEY;
    config.device_name = DEVICE_NAME;
    config.enable_derp = true;
    config.enable_disco = true;
    config.enable_stun = true;

    // Initialize
    ESP_LOGI(TAG, "Initializing MicroLink...");
    g_microlink = microlink_init(&config);
    if (!g_microlink) {
        ESP_LOGE(TAG, "MicroLink init failed");
        return;
    }

    // Connect
    ESP_LOGI(TAG, "Connecting to Tailscale...");
    microlink_connect(g_microlink);

    // Wait for connection
    ESP_LOGI(TAG, "Waiting for Tailscale connection...");
    while (!microlink_is_connected(g_microlink)) {
        microlink_update(g_microlink);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // Show connection info
    uint32_t vpn_ip = microlink_get_vpn_ip(g_microlink);
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "  CONNECTED!");
    ESP_LOGI(TAG, "  VPN IP: %s", microlink_vpn_ip_to_str(vpn_ip, ip_str));
    ESP_LOGI(TAG, "  Sending to: %s:%d",
             microlink_vpn_ip_to_str(g_server_ip, ip_str), SERVER_PORT);
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "");

    // Start sensor and receiver tasks
    xTaskCreate(sensor_task, "sensor", 4096, NULL, 5, NULL);
    xTaskCreate(receiver_task, "receiver", 4096, NULL, 5, NULL);

    // Main loop - just update MicroLink state machine
    while (1) {
        microlink_update(g_microlink);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

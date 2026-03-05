/**
 * @file main.c
 * @brief UDP Netcat Example - Bidirectional UDP over Tailscale
 *
 * This example demonstrates bidirectional UDP communication over Tailscale VPN,
 * equivalent to using netcat on Linux:
 *
 * FROM PC TO ESP32:
 *   PC:    echo -n "hello from PC" | nc -u <ESP32_TAILSCALE_IP> 9000
 *   ESP32: Prints "Received: hello from PC" AND immediately echoes back!
 *
 * FROM ESP32 TO PC:
 *   PC:    nc -u -l 9000
 *   ESP32: Sends "hello from ESP32" on timer
 *
 * ECHO MODE: When ESP32 receives a message, it IMMEDIATELY echoes back
 * with "ECHO: <original message>" - this tests round-trip latency!
 *
 * Uses callback-based reception for consistent, low-latency packet handling.
 *
 * This validates that the MicroLink UDP transport layer works correctly
 * for bidirectional communication.
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "microlink.h"

static const char *TAG = "udp_netcat";

/* Global counters for callback */
static volatile uint32_t g_rx_count = 0;

/* ============================================================================
 * CONFIGURATION - CHANGE THESE VALUES FOR YOUR SETUP
 * ========================================================================== */

#define WIFI_SSID          "YOUR_WIFI_SSID"
#define WIFI_PASSWORD      "YOUR_WIFI_PASSWORD"
#define TAILSCALE_AUTH_KEY "tskey-auth-XXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

/* Target peer (your PC running nc -u -l 9000) */
#define TARGET_PEER_IP     "100.x.x.x"  /* Your PC's Tailscale IP */
#define UDP_PORT           9000

/* How often to send test messages (ms) - 30 seconds to reduce heat/power */
#define SEND_INTERVAL_MS   30000

/* Enable immediate echo-back for latency testing */
#define ECHO_MODE_ENABLED  1

/* ============================================================================
 * WiFi Setup
 * ========================================================================== */

static bool wifi_connected = false;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_connected = false;
        ESP_LOGW(TAG, "WiFi disconnected, reconnecting...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected: " IPSTR, IP2STR(&event->ip_info.ip));
        wifi_connected = true;
    }
}

static void wifi_init(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASSWORD,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // CRITICAL: Disable WiFi power save to prevent UDP packet loss!
    // Power save mode can cause the ESP32 to miss incoming UDP packets
    // while the radio is in sleep state.
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_LOGI(TAG, "WiFi power save DISABLED for reliable UDP reception");
}

/* ============================================================================
 * UDP RX Callback - Called from high-priority task
 * ========================================================================== */

static void udp_rx_callback(microlink_udp_socket_t *sock,
                             uint32_t src_ip, uint16_t src_port,
                             const uint8_t *data, size_t len,
                             void *user_arg) {
    g_rx_count++;

    /* Null-terminate for safe printing (make a copy) */
    char data_str[512];
    size_t copy_len = (len < sizeof(data_str) - 1) ? len : sizeof(data_str) - 1;
    memcpy(data_str, data, copy_len);
    data_str[copy_len] = '\0';

    char src_ip_str[16];
    microlink_vpn_ip_to_str(src_ip, src_ip_str);

    printf("\n");
    printf("################################################################################\n");
    printf("##                                                                            ##\n");
    printf("##   ██████╗ ██╗  ██╗    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    ##\n");
    printf("##   ██╔══██╗╚██╗██╔╝    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    ##\n");
    printf("##   ██████╔╝ ╚███╔╝     ██████╔╝███████║██║     █████╔╝ █████╗     ██║       ##\n");
    printf("##   ██╔══██╗ ██╔██╗     ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       ##\n");
    printf("##   ██║  ██║██╔╝ ██╗    ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       ##\n");
    printf("##   ╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ##\n");
    printf("##                                                                            ##\n");
    printf("##  PACKET #%-5lu                                                            ##\n", (unsigned long)g_rx_count);
    printf("##  From: %-20s Port: %-5u                                   ##\n", src_ip_str, src_port);
    printf("##  Size: %-5u bytes                                                        ##\n", (unsigned)len);
    printf("##                                                                            ##\n");
    printf("##  DATA: \"%s\"\n", data_str);
    printf("##                                                                            ##\n");
    printf("################################################################################\n");

    /* Print hex dump for binary data */
    if (len <= 64) {
        printf("  Hex: ");
        for (size_t i = 0; i < len; i++) {
            printf("%02x ", data[i]);
        }
        printf("\n");
    }

#if ECHO_MODE_ENABLED
    /* IMMEDIATE ECHO: Send back the received message ASAP! */
    int64_t rx_time_us = esp_timer_get_time();

    char echo_buffer[600];
    snprintf(echo_buffer, sizeof(echo_buffer), "ECHO: %s", data_str);

    esp_err_t echo_err = microlink_udp_send(sock, src_ip, src_port,
                                             echo_buffer, strlen(echo_buffer));

    int64_t echo_time_us = esp_timer_get_time();
    int64_t echo_latency_us = echo_time_us - rx_time_us;

    if (echo_err == ESP_OK) {
        printf("\n");
        printf("  ╔══════════════════════════════════════════════════════════════════════╗\n");
        printf("  ║  >>> ECHO SENT BACK! <<<                                             ║\n");
        printf("  ║  To: %s:%u                                                  \n", src_ip_str, src_port);
        printf("  ║  Echo latency: %lld us (%.2f ms)                                    \n",
               (long long)echo_latency_us, echo_latency_us / 1000.0);
        printf("  ║  Response: \"%s\"\n", echo_buffer);
        printf("  ╚══════════════════════════════════════════════════════════════════════╝\n");
    } else {
        printf("  [ECHO FAILED: err=%d - WireGuard handshake may be pending]\n", echo_err);
    }
#endif
    printf("\n");
}

/* ============================================================================
 * Main Application
 * ========================================================================== */

void app_main(void) {
    printf("\n");
    printf("################################################################################\n");
    printf("##                                                                            ##\n");
    printf("##   ██╗   ██╗██████╗ ██████╗     ███╗   ██╗███████╗████████╗ ██████╗ █████╗ ████████╗   ##\n");
    printf("##   ██║   ██║██╔══██╗██╔══██╗    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝   ##\n");
    printf("##   ██║   ██║██║  ██║██████╔╝    ██╔██╗ ██║█████╗     ██║   ██║     ███████║   ██║      ##\n");
    printf("##   ██║   ██║██║  ██║██╔═══╝     ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║   ██║      ##\n");
    printf("##   ╚██████╔╝██████╔╝██║         ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║   ██║      ##\n");
    printf("##    ╚═════╝ ╚═════╝ ╚═╝         ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝      ##\n");
    printf("##                                                                            ##\n");
    printf("##            Bidirectional UDP over Tailscale VPN - ECHO MODE                ##\n");
    printf("##                                                                            ##\n");
    printf("################################################################################\n");
    printf("\n");

    /* Initialize NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Connect to WiFi */
    wifi_init();
    ESP_LOGI(TAG, "Connecting to WiFi '%s'...", WIFI_SSID);
    while (!wifi_connected) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    /* Initialize MicroLink (Tailscale VPN) */
    microlink_config_t ml_config = {
        .auth_key = TAILSCALE_AUTH_KEY,
        .device_name = microlink_get_device_name(),
        .enable_derp = true,
        .enable_stun = true,
        .enable_disco = true,
        .max_peers = 16,
    };

    microlink_t *ml = microlink_init(&ml_config);
    if (!ml) {
        ESP_LOGE(TAG, "Failed to initialize MicroLink");
        return;
    }

    /* Connect to Tailscale */
    ESP_LOGI(TAG, "Connecting to Tailscale VPN...");
    microlink_connect(ml);

    while (!microlink_is_connected(ml)) {
        microlink_update(ml);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    /* Wait for peers to be loaded from coordination server */
    ESP_LOGI(TAG, "Waiting for peer list to be fetched...");
    int wait_count = 0;
    while (microlink_get_peer_count(ml) == 0 && wait_count < 100) {
        microlink_update(ml);
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
        if (wait_count % 10 == 0) {
            ESP_LOGI(TAG, "  Still waiting for peers... (%d seconds)", wait_count / 10);
        }
    }

    if (microlink_get_peer_count(ml) == 0) {
        ESP_LOGW(TAG, "No peers found after 10 seconds - continuing anyway");
    } else {
        ESP_LOGI(TAG, "Loaded %d peers from Tailscale", microlink_get_peer_count(ml));
    }

    /* Get our VPN IP */
    uint32_t our_vpn_ip = microlink_get_vpn_ip(ml);
    char our_ip_str[16];
    microlink_vpn_ip_to_str(our_vpn_ip, our_ip_str);

    printf("\n");
    printf("################################################################################\n");
    printf("##                                                                            ##\n");
    printf("##                         *** CONNECTED! ***                                 ##\n");
    printf("##                                                                            ##\n");
    printf("##  ESP32 VPN IP:  %-57s##\n", our_ip_str);
    printf("##  Listening on:  UDP port %-48d##\n", UDP_PORT);
    printf("##  Target peer:   %-57s##\n", TARGET_PEER_IP);
    printf("##  Echo mode:     %-57s##\n", ECHO_MODE_ENABLED ? "ENABLED (immediate echo-back)" : "DISABLED");
    printf("##                                                                            ##\n");
    printf("################################################################################\n");
    printf("\n");

    /* Wait a bit for WireGuard handshakes to complete */
    ESP_LOGI(TAG, "Waiting for WireGuard handshakes (2 seconds)...");
    for (int i = 0; i < 20; i++) {
        microlink_update(ml);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    /* Create UDP socket bound to our port - retry if MicroLink briefly disconnects */
    microlink_udp_socket_t *sock = NULL;
    for (int retry = 0; retry < 10 && !sock; retry++) {
        if (!microlink_is_connected(ml)) {
            ESP_LOGW(TAG, "MicroLink disconnected, waiting to reconnect (attempt %d/10)...", retry + 1);
            for (int j = 0; j < 20 && !microlink_is_connected(ml); j++) {
                microlink_update(ml);
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }
        sock = microlink_udp_create(ml, UDP_PORT);
        if (!sock && retry < 9) {
            ESP_LOGW(TAG, "UDP socket creation failed, retrying in 1 second...");
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }
    if (!sock) {
        ESP_LOGE(TAG, "Failed to create UDP socket after 10 attempts!");
        return;
    }
    ESP_LOGI(TAG, "UDP socket created on port %d", UDP_PORT);

    /* Register RX callback for immediate packet handling */
    microlink_udp_set_rx_callback(sock, udp_rx_callback, NULL);
    ESP_LOGI(TAG, "RX callback registered - packets will be handled by high-priority task");

    /* Parse target IP */
    uint32_t target_ip = microlink_parse_ip(TARGET_PEER_IP);
    if (target_ip == 0) {
        ESP_LOGE(TAG, "Invalid target IP: %s", TARGET_PEER_IP);
        return;
    }

    /* Print test instructions and READY banner */
    printf("\n");
    printf("################################################################################\n");
    printf("##                                                                            ##\n");
    printf("##                    *** READY FOR COMMUNICATION! ***                        ##\n");
    printf("##                                                                            ##\n");
    printf("##  UDP socket listening on port %d - you can now send/receive!              ##\n", UDP_PORT);
    printf("##                                                                            ##\n");
    printf("################################################################################\n");
    printf("\n");
    printf("================================================================================\n");
    printf("                           TEST INSTRUCTIONS                                    \n");
    printf("================================================================================\n");
    printf("\n");
    printf("  TO RECEIVE FROM ESP32 (run on PC %s):\n", TARGET_PEER_IP);
    printf("    nc -u -l %d\n", UDP_PORT);
    printf("\n");
    printf("  TO SEND TO ESP32 (from any Tailscale peer):\n");
    printf("    echo -n 'hello' | nc -u %s %d\n", our_ip_str, UDP_PORT);
    printf("\n");
    printf("  FOR INTERACTIVE MODE (bidirectional chat):\n");
    printf("    nc -u %s %d\n", our_ip_str, UDP_PORT);
    printf("    (Type messages and press Enter - ESP32 will echo them back!)\n");
    printf("\n");
    printf("================================================================================\n");
    printf("\n");

    /* Main loop variables */
    uint64_t last_send_ms = 0;
    uint32_t msg_counter = 0;
    uint32_t tx_count = 0;

    ESP_LOGI(TAG, "Starting main loop - sending every %d seconds...", SEND_INTERVAL_MS / 1000);
    ESP_LOGI(TAG, "RX handled by callback - packets will print automatically!");
    printf("\n");

    /* Main loop - RX is handled by callback, only need to handle TX and MicroLink updates */
    while (1) {
        uint64_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

        /* ================================================================
         * SEND: Periodically send UDP packets to target
         * Equivalent to: echo -n "message" | nc -u TARGET_IP 9000
         * ================================================================ */
        if (now_ms - last_send_ms >= SEND_INTERVAL_MS) {
            msg_counter++;
            tx_count++;

            /* Build message */
            char tx_buffer[128];
            snprintf(tx_buffer, sizeof(tx_buffer),
                     "Hello from ESP32! msg #%lu, uptime=%lu sec",
                     (unsigned long)msg_counter,
                     (unsigned long)(now_ms / 1000));

            /* Send it */
            esp_err_t tx_err = microlink_udp_send(sock, target_ip, UDP_PORT,
                                                   tx_buffer, strlen(tx_buffer));

            if (tx_err == ESP_OK) {
                printf("\n");
                printf("  ┌──────────────────────────────────────────────────────────────────────┐\n");
                printf("  │  >>> TX PACKET #%-5lu <<<                                           │\n", (unsigned long)tx_count);
                printf("  │  To: %s:%d                                                 \n", TARGET_PEER_IP, UDP_PORT);
                printf("  │  Data: \"%s\"\n", tx_buffer);
                printf("  └──────────────────────────────────────────────────────────────────────┘\n");
            } else {
                ESP_LOGW(TAG, "[TX #%lu] FAILED (err=%d) - WireGuard handshake may be pending",
                         (unsigned long)tx_count, tx_err);
                ESP_LOGI(TAG, "  Tip: Run 'tailscale ping %s' from PC to speed up handshake",
                         our_ip_str);
            }

            last_send_ms = now_ms;
        }

        /* Keep MicroLink/Tailscale alive */
        microlink_update(ml);

        /* Main loop doesn't need to be fast since RX is handled by callback */
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

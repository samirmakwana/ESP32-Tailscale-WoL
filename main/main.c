#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "microlink.h"

// ─── Configuration ────────────────────────────────────────────────────────────
#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASSWORD   "YOUR_WIFI_PASSWORD"
#define TS_AUTH_KEY     "tskey-auth-XXXXXXXXX"
#define DEVICE_NAME     "TSD"

// Broadcast address of your LAN — change if your subnet differs
#define LAN_BROADCAST   "192.168.1.255"
#define WOL_PORT        9
// ─────────────────────────────────────────────────────────────────────────────

static const char *TAG      = "example";
static const char *TAG_WOL  = "wol";

static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

// ─── WiFi Event Handler ───────────────────────────────────────────────────────
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi disconnected, reconnecting...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi connected! IP: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "Connected to SSID: %s", WIFI_SSID);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// ─── WiFi Init ────────────────────────────────────────────────────────────────
static void wifi_init(void) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                &wifi_event_handler, NULL));

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid     = WIFI_SSID,
            .password = WIFI_PASSWORD,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to WiFi...");
    xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT,
                        pdFALSE, pdTRUE, portMAX_DELAY);
}

// ─── Wake-on-LAN ─────────────────────────────────────────────────────────────
static esp_err_t send_wol_packet(const char *mac_str) {
    uint8_t mac[6];

    // Parse MAC address (accepts AA:BB:CC:DD:EE:FF format)
    if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2],
               &mac[3], &mac[4], &mac[5]) != 6) {
        ESP_LOGE(TAG_WOL, "Invalid MAC address format: %s", mac_str);
        return ESP_ERR_INVALID_ARG;
    }

    // Build magic packet: 6 bytes of 0xFF + target MAC repeated 16 times = 102 bytes
    uint8_t packet[102];
    memset(packet, 0xFF, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(packet + 6 + i * 6, mac, 6);
    }

    // Send as UDP broadcast on port 9
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG_WOL, "Failed to create socket");
        return ESP_FAIL;
    }

    int broadcast = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct sockaddr_in dest = {
        .sin_family      = AF_INET,
        .sin_port        = htons(WOL_PORT),
        .sin_addr.s_addr = inet_addr(LAN_BROADCAST),
    };

    int sent = sendto(sock, packet, sizeof(packet), 0,
                      (struct sockaddr *)&dest, sizeof(dest));
    close(sock);

    if (sent < 0) {
        ESP_LOGE(TAG_WOL, "Failed to send magic packet");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG_WOL, "Magic packet sent to %s via %s:%d",
             mac_str, LAN_BROADCAST, WOL_PORT);
    return ESP_OK;
}

// ─── HTTP Handler: GET /wol?mac=AA:BB:CC:DD:EE:FF ────────────────────────────
static esp_err_t wol_handler(httpd_req_t *req) {
    char mac[18]    = {0};
    char query[64]  = {0};

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "mac", mac, sizeof(mac));
    }

    if (strlen(mac) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Missing 'mac' parameter. Usage: /wol?mac=AA:BB:CC:DD:EE:FF");
        return ESP_FAIL;
    }

    esp_err_t ret = send_wol_packet(mac);
    if (ret == ESP_OK) {
        char resp[64];
        snprintf(resp, sizeof(resp), "Magic packet sent to %s\n", mac);
        httpd_resp_sendstr(req, resp);
    } else if (ret == ESP_ERR_INVALID_ARG) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Invalid MAC address. Use format AA:BB:CC:DD:EE:FF");
    } else {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Failed to send magic packet");
    }

    return ESP_OK;
}

// ─── HTTP Server Init ─────────────────────────────────────────────────────────
static void start_http_server(void) {
    httpd_handle_t server     = NULL;
    httpd_config_t config     = HTTPD_DEFAULT_CONFIG();
    config.stack_size         = 8192;
    config.server_port        = 80;

    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG_WOL, "Failed to start HTTP server");
        return;
    }

    httpd_uri_t wol_uri = {
        .uri      = "/wol",
        .method   = HTTP_GET,
        .handler  = wol_handler,
        .user_ctx = NULL,
    };
    httpd_register_uri_handler(server, &wol_uri);

    ESP_LOGI(TAG_WOL, "HTTP server started on port 80");
    ESP_LOGI(TAG_WOL, "WoL endpoint: http://<vpn-ip>/wol?mac=AA:BB:CC:DD:EE:FF");
}

// ─── MicroLink Task ───────────────────────────────────────────────────────────
static void microlink_task(void *pvParameters) {
    ESP_LOGI(TAG, "=== MicroLink Basic Connect Example ===");

    microlink_config_t config;
    microlink_get_default_config(&config);
    config.auth_key     = TS_AUTH_KEY;
    config.device_name  = DEVICE_NAME;
    config.enable_derp  = true;
    config.enable_disco = true;
    config.enable_stun  = true;

    ESP_LOGI(TAG, "Initializing MicroLink...");
    microlink_t *ml = microlink_init(&config);
    if (!ml) {
        ESP_LOGE(TAG, "MicroLink init failed");
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Connecting to Tailscale...");
    microlink_connect(ml);

    microlink_state_t last_state = MICROLINK_STATE_IDLE;

    while (1) {
        microlink_update(ml);

        // Log state transitions
        microlink_state_t state = microlink_get_state(ml);
        if (state != last_state) {
            ESP_LOGI(TAG, "State: %s -> %s",
                     microlink_state_to_str(last_state),
                     microlink_state_to_str(state));
            last_state = state;

            // Print connection info once fully connected
            if (state == MICROLINK_STATE_CONNECTED ||
                state == MICROLINK_STATE_MONITORING) {

                char ip_str[16];
                microlink_vpn_ip_to_str(microlink_get_vpn_ip(ml), ip_str);

                ESP_LOGI(TAG, "*** TAILSCALE CONNECTED ***");
                ESP_LOGI(TAG, "");
                ESP_LOGI(TAG, "===================================");
                ESP_LOGI(TAG, "  VPN IP: %s", ip_str);
                ESP_LOGI(TAG, "  WoL:    curl http://%s/wol?mac=AA:BB:CC:DD:EE:FF", ip_str);
                ESP_LOGI(TAG, "===================================");
                ESP_LOGI(TAG, "");

                // Print peer list
                const microlink_peer_t *peers;
                uint8_t peer_count;
                if (microlink_get_peers(ml, &peers, &peer_count) == ESP_OK) {
                    ESP_LOGI(TAG, "Peers (%d):", peer_count);
                    for (int i = 0; i < peer_count; i++) {
                        char peer_ip[16];
                        microlink_vpn_ip_to_str(peers[i].vpn_ip, peer_ip);
                        ESP_LOGI(TAG, "  - %s (%s)", peers[i].hostname, peer_ip);
                    }
                }
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ─── Entry Point ─────────────────────────────────────────────────────────────
void app_main(void) {
    wifi_init();

    // Start WoL HTTP server (runs on port 80, accessible over Tailscale)
    start_http_server();

    // Start MicroLink in a dedicated task with 32KB stack (needed for TLS handshake)
    xTaskCreate(microlink_task, "microlink", 32768, NULL, 6, NULL);
}

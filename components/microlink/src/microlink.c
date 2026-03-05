/**
 * @file microlink.c
 * @brief MicroLink main implementation
 */

#include "microlink.h"
#include "microlink_internal.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_mac.h"

static const char *TAG = "microlink";

/* Static buffer for auto-generated device name */
static char s_device_name[20] = {0};

/* ============================================================================
 * Default Configuration
 * ========================================================================== */

const char *microlink_get_device_name(void) {
    if (s_device_name[0] == '\0') {
        // Generate from WiFi MAC address (last 3 bytes)
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(s_device_name, sizeof(s_device_name), "esp32-%02x%02x%02x",
                 mac[3], mac[4], mac[5]);
    }
    return s_device_name;
}

void microlink_get_default_config(microlink_config_t *config) {
    memset(config, 0, sizeof(microlink_config_t));

    config->auth_key = NULL;           // Must be set by user
    config->device_name = microlink_get_device_name();  // Auto-generated from MAC
    config->enable_derp = true;
    config->enable_stun = true;
    config->enable_disco = true;
    config->max_peers = MICROLINK_MAX_PEERS;
    config->heartbeat_interval_ms = MICROLINK_HEARTBEAT_INTERVAL_MS;
}

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

uint64_t microlink_get_time_ms(void) {
    return esp_timer_get_time() / 1000;
}

const char *microlink_vpn_ip_to_str(uint32_t vpn_ip, char *buffer) {
    snprintf(buffer, 16, "%lu.%lu.%lu.%lu",
             (vpn_ip >> 24) & 0xFF,
             (vpn_ip >> 16) & 0xFF,
             (vpn_ip >> 8) & 0xFF,
             vpn_ip & 0xFF);
    return buffer;
}

int microlink_get_peer_count(const microlink_t *ml) {
    if (!ml) return 0;
    return ml->peer_count;
}

const char *microlink_state_to_str(microlink_state_t state) {
    switch (state) {
        case MICROLINK_STATE_IDLE: return "IDLE";
        case MICROLINK_STATE_REGISTERING: return "REGISTERING";
        case MICROLINK_STATE_FETCHING_PEERS: return "FETCHING_PEERS";
        case MICROLINK_STATE_CONFIGURING_WG: return "CONFIGURING_WG";
        case MICROLINK_STATE_CONNECTED: return "CONNECTED";
        case MICROLINK_STATE_MONITORING: return "MONITORING";
        case MICROLINK_STATE_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

uint8_t microlink_peer_find_by_vpn_ip(const microlink_t *ml, uint32_t vpn_ip) {
    uint8_t last_byte = vpn_ip & 0xFF;
    if (last_byte >= MICROLINK_PEER_MAP_SIZE) {
        return 0xFF;  // Invalid
    }

    uint8_t idx = ml->peer_map[last_byte];
    if (idx >= ml->peer_count) {
        return 0xFF;  // Not found
    }

    // Verify match
    if (ml->peers[idx].vpn_ip == vpn_ip) {
        return idx;
    }

    return 0xFF;  // Not found
}

esp_err_t microlink_queue_rx_packet(microlink_t *ml, const microlink_packet_t *pkt) {
    uint8_t next_head = (ml->rx_head + 1) % MICROLINK_RX_QUEUE_SIZE;
    if (next_head == ml->rx_tail) {
        ml->stats.packets_dropped++;
        ESP_LOGW(TAG, "RX queue full, dropping packet");
        return ESP_ERR_NO_MEM;
    }

    memcpy(&ml->rx_queue[ml->rx_head], pkt, sizeof(microlink_packet_t));
    ml->rx_head = next_head;
    ml->stats.packets_received++;
    ml->stats.bytes_received += pkt->len;

    return ESP_OK;
}

esp_err_t microlink_queue_tx_packet(microlink_t *ml, const microlink_packet_t *pkt) {
    uint8_t next_head = (ml->tx_head + 1) % MICROLINK_TX_QUEUE_SIZE;
    if (next_head == ml->tx_tail) {
        ml->stats.packets_dropped++;
        ESP_LOGW(TAG, "TX queue full, dropping packet");
        return ESP_ERR_NO_MEM;
    }

    memcpy(&ml->tx_queue[ml->tx_head], pkt, sizeof(microlink_packet_t));
    ml->tx_head = next_head;

    return ESP_OK;
}

/* ============================================================================
 * Initialization & Deinitialization
 * ========================================================================== */

microlink_t *microlink_init(const microlink_config_t *config) {
    if (!config || !config->auth_key || !config->device_name) {
        ESP_LOGE(TAG, "Invalid configuration");
        return NULL;
    }

    // Allocate context
    microlink_t *ml = calloc(1, sizeof(microlink_t));
    if (!ml) {
        ESP_LOGE(TAG, "Failed to allocate context");
        return NULL;
    }

    // Copy configuration
    memcpy(&ml->config, config, sizeof(microlink_config_t));

    // Initialize peer map
    memset(ml->peer_map, 0xFF, sizeof(ml->peer_map));

    // Set initial state
    ml->state = MICROLINK_STATE_IDLE;
    ml->prev_state = MICROLINK_STATE_IDLE;
    ml->state_enter_time_ms = microlink_get_time_ms();

    ESP_LOGI(TAG, "MicroLink v%s initialized", MICROLINK_VERSION);
    ESP_LOGI(TAG, "Device: %s", ml->config.device_name);
    ESP_LOGI(TAG, "Features: DERP=%d STUN=%d DISCO=%d",
             ml->config.enable_derp, ml->config.enable_stun, ml->config.enable_disco);

    return ml;
}

void microlink_deinit(microlink_t *ml) {
    if (!ml) return;

    // Disconnect if connected
    if (ml->state != MICROLINK_STATE_IDLE) {
        microlink_disconnect(ml);
    }

    // Clean up subsystems
    microlink_coordination_deinit(ml);
    microlink_wireguard_deinit(ml);

    if (ml->config.enable_derp) {
        microlink_derp_deinit(ml);
    }

    if (ml->config.enable_stun) {
        microlink_stun_deinit(ml);
    }

    // Clean up DISCO
    microlink_disco_deinit(ml);

    // Free context
    free(ml);

    ESP_LOGI(TAG, "MicroLink deinitialized");
}

/* ============================================================================
 * Connection Management
 * ========================================================================== */

esp_err_t microlink_connect(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    if (ml->state != MICROLINK_STATE_IDLE) {
        ESP_LOGW(TAG, "Already connecting or connected");
        return ESP_ERR_INVALID_STATE;
    }

    ESP_LOGI(TAG, "Starting connection process...");

    // Initialize subsystems
    esp_err_t ret;

    // 1. Initialize coordination client
    ret = microlink_coordination_init(ml);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize coordination client: %d", ret);
        microlink_set_state(ml, MICROLINK_STATE_ERROR);
        return ret;
    }

    // 2. Initialize WireGuard
    ret = microlink_wireguard_init(ml);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WireGuard: %d", ret);
        microlink_set_state(ml, MICROLINK_STATE_ERROR);
        return ret;
    }

    // 3. Initialize optional subsystems
    if (ml->config.enable_stun) {
        ret = microlink_stun_init(ml);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "STUN init failed, continuing without: %d", ret);
        }
    }

    if (ml->config.enable_derp) {
        ret = microlink_derp_init(ml);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "DERP init failed, continuing without: %d", ret);
        }
    }

    if (ml->config.enable_disco) {
        ret = microlink_disco_init(ml);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "DISCO init failed, continuing without: %d", ret);
        }
    }

    // Start state machine
    microlink_set_state(ml, MICROLINK_STATE_REGISTERING);

    return ESP_OK;
}

esp_err_t microlink_disconnect(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    ESP_LOGI(TAG, "Disconnecting...");

    // Clean up subsystems
    microlink_coordination_deinit(ml);
    microlink_wireguard_deinit(ml);

    if (ml->config.enable_derp) {
        microlink_derp_deinit(ml);
    }

    if (ml->config.enable_stun) {
        microlink_stun_deinit(ml);
    }

    if (ml->config.enable_disco) {
        microlink_disco_deinit(ml);
    }

    // Clear state
    ml->vpn_ip = 0;
    ml->peer_count = 0;
    memset(&ml->stats, 0, sizeof(microlink_stats_t));

    // Trigger callback
    if (ml->config.on_disconnected) {
        ml->config.on_disconnected();
    }

    microlink_set_state(ml, MICROLINK_STATE_IDLE);

    return ESP_OK;
}

esp_err_t microlink_update(microlink_t *ml) {
    if (!ml) return ESP_ERR_INVALID_ARG;

    // Run state machine
    microlink_state_machine(ml);

    // Process queued TX packets
    while (ml->tx_tail != ml->tx_head) {
        microlink_packet_t *pkt = &ml->tx_queue[ml->tx_tail];

        // Try WireGuard direct first
        esp_err_t ret = microlink_wireguard_send(ml, pkt->dest_vpn_ip,
                                                 pkt->data, pkt->len);

        if (ret != ESP_OK && ml->config.enable_derp) {
            // Fallback to DERP
            ret = microlink_derp_send(ml, pkt->dest_vpn_ip, pkt->data, pkt->len);
        }

        if (ret == ESP_OK) {
            ml->stats.packets_sent++;
            ml->stats.bytes_sent += pkt->len;
        }

        ml->tx_tail = (ml->tx_tail + 1) % MICROLINK_TX_QUEUE_SIZE;
    }

    // Try to receive packets
    microlink_wireguard_receive(ml);

    if (ml->config.enable_derp) {
        microlink_derp_receive(ml);
    }

    return ESP_OK;
}

/* ============================================================================
 * Data Transfer
 * ========================================================================== */

esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                         const uint8_t *data, size_t len) {
    if (!ml || !data || len == 0 || len > MICROLINK_NETWORK_BUFFER_SIZE) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!microlink_is_connected(ml)) {
        return ESP_ERR_INVALID_STATE;
    }

    // Queue packet for transmission
    microlink_packet_t pkt = {
        .src_vpn_ip = ml->vpn_ip,
        .dest_vpn_ip = dest_vpn_ip,
        .len = len,
        .timestamp_ms = microlink_get_time_ms()
    };
    memcpy(pkt.data, data, len);

    return microlink_queue_tx_packet(ml, &pkt);
}

esp_err_t microlink_receive(microlink_t *ml, uint32_t *src_vpn_ip,
                            uint8_t *buffer, size_t *len) {
    if (!ml || !src_vpn_ip || !buffer || !len) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!microlink_is_connected(ml)) {
        return ESP_ERR_INVALID_STATE;
    }

    // Check if queue empty
    if (ml->rx_tail == ml->rx_head) {
        return ESP_ERR_NOT_FOUND;
    }

    // Dequeue packet
    microlink_packet_t *pkt = &ml->rx_queue[ml->rx_tail];

    if (*len < pkt->len) {
        return ESP_ERR_INVALID_SIZE;
    }

    *src_vpn_ip = pkt->src_vpn_ip;
    *len = pkt->len;
    memcpy(buffer, pkt->data, pkt->len);

    ml->rx_tail = (ml->rx_tail + 1) % MICROLINK_RX_QUEUE_SIZE;

    return ESP_OK;
}

/* ============================================================================
 * Status Queries
 * ========================================================================== */

microlink_state_t microlink_get_state(const microlink_t *ml) {
    return ml ? ml->state : MICROLINK_STATE_IDLE;
}

bool microlink_is_connected(const microlink_t *ml) {
    if (!ml) return false;
    return (ml->state == MICROLINK_STATE_CONNECTED ||
            ml->state == MICROLINK_STATE_MONITORING);
}

uint32_t microlink_get_vpn_ip(const microlink_t *ml) {
    return ml ? ml->vpn_ip : 0;
}

esp_err_t microlink_get_peers(const microlink_t *ml,
                              const microlink_peer_t **peers,
                              uint8_t *count) {
    if (!ml || !peers || !count) {
        return ESP_ERR_INVALID_ARG;
    }

    *peers = ml->peers;
    *count = ml->peer_count;
    return ESP_OK;
}

esp_err_t microlink_get_stats(const microlink_t *ml, microlink_stats_t *stats) {
    if (!ml || !stats) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(stats, &ml->stats, sizeof(microlink_stats_t));
    return ESP_OK;
}

uint32_t microlink_get_peer_latency(const microlink_t *ml, uint32_t peer_vpn_ip) {
    if (!ml) return UINT32_MAX;

    uint8_t idx = microlink_peer_find_by_vpn_ip(ml, peer_vpn_ip);
    if (idx == 0xFF) {
        return UINT32_MAX;
    }

    return ml->peers[idx].latency_ms;
}

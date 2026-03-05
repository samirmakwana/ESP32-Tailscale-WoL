/**
 * @file microlink_derp.c
 * @brief DERP relay client implementation
 *
 * DERP (Designated Encrypted Relay for Packets) provides NAT traversal
 * when direct WireGuard connections fail.
 *
 * Protocol: https://pkg.go.dev/tailscale.com/derp
 *
 * Frame format:
 *   [1 byte type][4 byte length (big-endian)][payload]
 */

#include "microlink_internal.h"
#include "nacl_box.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <lwip/sockets.h>
#include <errno.h>

static const char *TAG = "ml_derp";

/* DERP frame types */
#define DERP_MAGIC_LEN          6
#define DERP_SERVER_KEY_LEN     32
#define DERP_CLIENT_INFO_LEN    32  // Public key

/* Frame types from server (per https://pkg.go.dev/tailscale.com/derp) */
#define FRAME_SERVER_KEY        0x01  // Server's public key (8B magic + 32B pubkey)
#define FRAME_SERVER_INFO       0x03  // Server info (24B nonce + encrypted JSON)
#define FRAME_RECV_PACKET       0x05  // Received packet from peer (32B src key + payload)
#define FRAME_KEEP_ALIVE        0x06  // Keep-alive from server (no data)
#define FRAME_PEER_GONE         0x08  // Peer disconnected from this DERP (32B key + 1B reason)
#define FRAME_PEER_PRESENT      0x09  // Peer is present on this DERP (32B key + optional data)
#define FRAME_PING              0x12  // Ping from server (8 bytes data)
#define FRAME_PONG              0x13  // Pong response (8 bytes echo)
#define FRAME_HEALTH            0x14  // Health check (text message)
#define FRAME_SERVER_RESTART    0x15  // Server restarting soon (timing data)

/* Frame types from client (per https://pkg.go.dev/tailscale.com/derp) */
#define FRAME_CLIENT_INFO       0x02  // Client info (32B pubkey + 24B nonce + encrypted JSON)
#define FRAME_SEND_PACKET       0x04  // Send packet to peer (32B dest key + payload)
#define FRAME_NOTE_PREFERRED    0x07  // Tell server this is our preferred DERP (1B bool)
#define FRAME_FORWARD_PACKET    0x0a  // Forward packet (mesh only: 32B src + 32B dest + payload)
#define FRAME_WATCH_CONNS       0x10  // Watch peer connections (mesh key required)
#define FRAME_CLOSE_PEER        0x11  // Close connection to peer (32B pubkey)

/* Note: Client keepalive is done via NotePreferred (0x07) or regular send activity */

/* DERP protocol version */
#define DERP_MAGIC              "DERP\x00\x01"  // "DERP" + version 0x0001

/* Timeouts */
#define DERP_CONNECT_TIMEOUT_MS 10000
#define DERP_READ_TIMEOUT_MS    100
#define DERP_KEEPALIVE_MS       30000

/* Maximum frame size */
#define DERP_MAX_FRAME_SIZE     (MICROLINK_NETWORK_BUFFER_SIZE + 64)

/* mbedTLS context for DERP */
static mbedtls_entropy_context derp_entropy;
static mbedtls_ctr_drbg_context derp_ctr_drbg;
static mbedtls_net_context derp_server_fd;
static bool derp_rng_initialized = false;

/* Receive buffer */
static uint8_t derp_rx_buffer[DERP_MAX_FRAME_SIZE];

/* Server's public key (received during handshake) */
static uint8_t derp_server_key[DERP_SERVER_KEY_LEN];

/* Current DERP server being used (for fallback support) */
static const char *current_derp_server = MICROLINK_DERP_SERVER;

/* Mutex for serializing ALL TLS operations (mbedtls SSL context is NOT thread-safe) */
/* Both read and write must be protected - concurrent access causes deadlock/corruption */
static SemaphoreHandle_t derp_tls_mutex = NULL;
static StaticSemaphore_t derp_tls_mutex_buffer;

/**
 * @brief Write exact number of bytes to TLS
 */
static int derp_tls_write_all(microlink_t *ml, const uint8_t *data, size_t len) {
    size_t written = 0;
    int retries = 0;
    const int max_retries = 20;  // 20 * 10ms = 200ms max (socket has 100ms timeout)

    ESP_LOGI(TAG, "[TLS-WR] >> len=%u stack=%lu", (unsigned int)len, (unsigned long)uxTaskGetStackHighWaterMark(NULL));

    while (written < len) {
        // Check socket state before write
        int sock_err = 0;
        socklen_t sock_err_len = sizeof(sock_err);
        getsockopt(ml->derp.sockfd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_len);

        ESP_LOGI(TAG, "[TLS-WR] ssl_write(%u) sock_err=%d fd=%d",
                 (unsigned int)(len - written), sock_err, ml->derp.sockfd);

        // Use select() to check if socket is writable BEFORE calling mbedtls
        // This prevents blocking inside mbedtls_ssl_write
        fd_set write_fds;
        struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };  // 50ms timeout
        FD_ZERO(&write_fds);
        FD_SET(ml->derp.sockfd, &write_fds);
        int sel_ret = select(ml->derp.sockfd + 1, NULL, &write_fds, NULL, &tv);
        if (sel_ret <= 0) {
            // Socket not writable - retry a few times before giving up
            if (++retries <= 5) {
                ESP_LOGW(TAG, "[TLS-WR] Socket not writable (select=%d errno=%d), retry %d/5",
                         sel_ret, errno, retries);
                vTaskDelay(pdMS_TO_TICKS(20));
                continue;
            }
            ESP_LOGW(TAG, "[TLS-WR] Socket not writable after 5 retries, giving up");
            return -1;
        }
        ESP_LOGI(TAG, "[TLS-WR] socket writable, calling ssl_write...");

        int ret = mbedtls_ssl_write(&ml->derp.ssl, data + written, len - written);
        ESP_LOGI(TAG, "[TLS-WR] ret=%d", ret);

        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                // Yield to other tasks to prevent busy-loop starvation
                ESP_LOGI(TAG, "[TLS-WR] WANT retry=%d yield", retries);
                vTaskDelay(pdMS_TO_TICKS(10));
                if (++retries > max_retries) {
                    ESP_LOGW(TAG, "TLS write timeout after %d retries (will retry later)", retries);
                    return -1;
                }
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                ESP_LOGW(TAG, "TLS write socket timeout");
                return -1;
            }
            ESP_LOGE(TAG, "TLS write failed: -0x%04x", -ret);
            return -1;
        }
        written += ret;
        retries = 0;  // Reset retry counter on successful write
    }
    ESP_LOGI(TAG, "[TLS-WR] << OK %u", (unsigned int)written);
    return (int)written;
}

/**
 * @brief Read exact number of bytes from TLS
 */
static int derp_tls_read_all(microlink_t *ml, uint8_t *data, size_t len, int timeout_ms) {
    size_t received = 0;
    uint64_t start_ms = microlink_get_time_ms();

    while (received < len) {
        if (timeout_ms > 0 && (microlink_get_time_ms() - start_ms) > (uint64_t)timeout_ms) {
            return -2;  // Timeout
        }

        int ret = mbedtls_ssl_read(&ml->derp.ssl, data + received, len - received);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ESP_LOGW(TAG, "Server closed connection");
                return -1;
            }
            ESP_LOGE(TAG, "TLS read failed: -0x%04x", -ret);
            return -1;
        }
        if (ret == 0) {
            // mbedtls_ssl_read returns 0 when connection is closed
            ESP_LOGW(TAG, "TLS connection closed by peer (received %d of %d bytes)",
                     (int)received, (int)len);
            return -1;
        }
        received += ret;
    }
    return (int)received;
}

/**
 * @brief Send a DERP frame (thread-safe with mutex)
 */
static esp_err_t derp_send_frame(microlink_t *ml, uint8_t type, const uint8_t *payload, uint32_t len) {
    ESP_LOGI(TAG, "[FRAME] >> type=0x%02x len=%lu", type, (unsigned long)len);

    // Initialize mutex on first use (static allocation for RTOS safety)
    if (derp_tls_mutex == NULL) {
        ESP_LOGI(TAG, "[FRAME] Creating TLS mutex");
        derp_tls_mutex = xSemaphoreCreateMutexStatic(&derp_tls_mutex_buffer);
        if (derp_tls_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create DERP TLS mutex");
            return ESP_FAIL;
        }
    }

    // Take mutex with SHORT timeout - if receive is in progress, skip this send
    // The WireGuard layer will retry, so it's okay to drop occasional sends
    // This mutex protects the entire SSL context (both read and write)
    ESP_LOGI(TAG, "[FRAME] TLS mutex take...");
    if (xSemaphoreTake(derp_tls_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        ESP_LOGW(TAG, "DERP TLS mutex busy - dropping send (WG will retry)");
        return ESP_ERR_TIMEOUT;
    }
    ESP_LOGI(TAG, "[FRAME] TLS mutex OK");

    esp_err_t result = ESP_OK;
    uint8_t header[5];
    header[0] = type;
    header[1] = (len >> 24) & 0xFF;
    header[2] = (len >> 16) & 0xFF;
    header[3] = (len >> 8) & 0xFF;
    header[4] = len & 0xFF;

    ESP_LOGI(TAG, "[FRAME] hdr write...");
    if (derp_tls_write_all(ml, header, 5) < 0) {
        ESP_LOGW(TAG, "[FRAME] hdr FAIL");
        result = ESP_FAIL;
        goto done;
    }

    if (len > 0 && payload != NULL) {
        ESP_LOGI(TAG, "[FRAME] payload write %lu...", (unsigned long)len);
        if (derp_tls_write_all(ml, payload, len) < 0) {
            ESP_LOGW(TAG, "[FRAME] payload FAIL");
            result = ESP_FAIL;
            goto done;
        }
    }

done:
    ESP_LOGI(TAG, "[FRAME] TLS mutex give");
    xSemaphoreGive(derp_tls_mutex);

    // CRITICAL: Yield to other tasks after TLS write to prevent starvation
    // This is especially important when WireGuard fires multiple handshake packets
    ESP_LOGI(TAG, "[FRAME] yield");
    vTaskDelay(pdMS_TO_TICKS(1));
    ESP_LOGI(TAG, "[FRAME] << result=%d", result);

    return result;
}

/**
 * @brief Receive a DERP frame header
 */
static esp_err_t derp_recv_frame_header(microlink_t *ml, uint8_t *type, uint32_t *len, int timeout_ms) {
    uint8_t header[5];
    int ret = derp_tls_read_all(ml, header, 5, timeout_ms);
    if (ret < 0) {
        return (ret == -2) ? ESP_ERR_TIMEOUT : ESP_FAIL;
    }

    *type = header[0];
    *len = ((uint32_t)header[1] << 24) |
           ((uint32_t)header[2] << 16) |
           ((uint32_t)header[3] << 8) |
           (uint32_t)header[4];

    return ESP_OK;
}

/**
 * @brief Send HTTP upgrade request for DERP
 */
static esp_err_t derp_send_http_upgrade(microlink_t *ml) {
    char request[512];
    int len = snprintf(request, sizeof(request),
        "GET /derp HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: DERP\r\n"
        "User-Agent: MicroLink/1.0\r\n"
        "\r\n",
        current_derp_server);

    ESP_LOGI(TAG, "Sending HTTP upgrade request to %s (%d bytes)",
             current_derp_server, len);

    if (derp_tls_write_all(ml, (uint8_t *)request, len) < 0) {
        ESP_LOGE(TAG, "Failed to send HTTP upgrade request");
        return ESP_FAIL;
    }

    // Read HTTP response (look for "101 Switching Protocols")
    uint8_t response[512];
    int total = 0;
    uint64_t start = microlink_get_time_ms();

    while (total < (int)sizeof(response) - 1) {
        if (microlink_get_time_ms() - start > 10000) {
            ESP_LOGE(TAG, "HTTP upgrade timeout after %d bytes", total);
            if (total > 0) {
                response[total] = '\0';
                ESP_LOGE(TAG, "Partial response: %s", response);
            }
            return ESP_ERR_TIMEOUT;
        }

        int ret = mbedtls_ssl_read(&ml->derp.ssl, response + total, 1);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            // Log partial response if we got any data
            if (total > 0) {
                response[total] = '\0';
                ESP_LOGE(TAG, "Failed to read HTTP response after %d bytes: -0x%04x", total, -ret);
                ESP_LOGE(TAG, "Partial response: %s", response);
            } else {
                ESP_LOGE(TAG, "Failed to read HTTP response (no data received): -0x%04x", -ret);
            }
            return ESP_FAIL;
        }
        if (ret == 0) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        total += ret;

        // Check for end of headers
        if (total >= 4 && memcmp(response + total - 4, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    response[total] = '\0';

    ESP_LOGI(TAG, "HTTP response (%d bytes): %.100s%s",
             total, response, total > 100 ? "..." : "");

    if (strstr((char *)response, "101") == NULL) {
        ESP_LOGE(TAG, "DERP upgrade failed, expected 101. Got: %s", response);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "HTTP upgrade to DERP successful");
    return ESP_OK;
}

/**
 * @brief Perform DERP handshake
 */
static esp_err_t derp_handshake(microlink_t *ml) {
    uint8_t type;
    uint32_t len;
    esp_err_t err;

    // Step 1: Receive server key frame
    ESP_LOGI(TAG, "Waiting for server key...");
    err = derp_recv_frame_header(ml, &type, &len, DERP_CONNECT_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to receive server key header");
        return err;
    }

    // Server key frame: type=0x01, contains [8-byte magic "DERP🔑"][32-byte server pubkey]
    // Total expected length: 40 bytes (8 magic + 32 key)
    #define DERP_MAGIC_BYTES 8
    if (type != FRAME_SERVER_KEY || len < (DERP_MAGIC_BYTES + DERP_SERVER_KEY_LEN)) {
        ESP_LOGE(TAG, "Unexpected frame: type=0x%02x len=%lu (expected SERVER_KEY with 40 bytes)", type, len);
        return ESP_FAIL;
    }

    // Read and verify the 8-byte magic "DERP🔑" (0x44 45 52 50 f0 9f 94 91)
    uint8_t magic[DERP_MAGIC_BYTES];
    if (derp_tls_read_all(ml, magic, DERP_MAGIC_BYTES, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read server key magic");
        return ESP_FAIL;
    }

    // Verify magic bytes (DERP + key emoji in UTF-8)
    static const uint8_t expected_magic[8] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};
    if (memcmp(magic, expected_magic, DERP_MAGIC_BYTES) != 0) {
        ESP_LOGE(TAG, "Invalid DERP magic: %02x%02x%02x%02x%02x%02x%02x%02x",
                 magic[0], magic[1], magic[2], magic[3],
                 magic[4], magic[5], magic[6], magic[7]);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "DERP magic verified");

    // Read the 32-byte server public key
    if (derp_tls_read_all(ml, derp_server_key, DERP_SERVER_KEY_LEN, DERP_CONNECT_TIMEOUT_MS) < 0) {
        ESP_LOGE(TAG, "Failed to read server key");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Received DERP server key");
    ESP_LOGI(TAG, "Server pubkey (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             derp_server_key[0], derp_server_key[1], derp_server_key[2], derp_server_key[3],
             derp_server_key[4], derp_server_key[5], derp_server_key[6], derp_server_key[7]);

    // Step 2: Send client info
    // Format: [32B our public key][24B nonce][naclbox(JSON)]
    // The JSON contains ClientInfo struct with Version field
    ESP_LOGI(TAG, "Sending client info...");

    // ClientInfo JSON with all required fields
    // Version: DERP protocol version (2 is current)
    // CanAckPings: We can respond to ping frames
    // IsProber: We are not a prober (health check client)
    const char *client_info_json = "{\"Version\":2,\"CanAckPings\":true,\"IsProber\":false}";
    size_t json_len = strlen(client_info_json);

    // Generate random nonce
    uint8_t nonce[NACL_BOX_NONCEBYTES];
    mbedtls_ctr_drbg_random(&derp_ctr_drbg, nonce, NACL_BOX_NONCEBYTES);

    // Encrypt JSON using NaCl box
    // DERP uses the NODE KEY (WireGuard key), NOT the machine key!
    // ciphertext = naclbox(plaintext, nonce, server_pubkey, our_node_privkey)
    // Ciphertext size = plaintext (49) + MAC (16) = 65 bytes minimum
    uint8_t ciphertext[128];  // Must be >= json_len + NACL_BOX_MACBYTES
    size_t ciphertext_len = json_len + NACL_BOX_MACBYTES;

    int box_ret = nacl_box(ciphertext,
                           (const uint8_t *)client_info_json, json_len,
                           nonce,
                           derp_server_key,              // Recipient: DERP server
                           ml->wireguard.private_key);   // Sender: our NODE key (WireGuard key)
    if (box_ret != 0) {
        ESP_LOGE(TAG, "Failed to encrypt client info");
        return ESP_FAIL;
    }

    // Build frame: [32B node pubkey][24B nonce][ciphertext]
    uint8_t client_info_frame[32 + NACL_BOX_NONCEBYTES + 128];
    size_t frame_len = 32 + NACL_BOX_NONCEBYTES + ciphertext_len;

    // Use NODE public key (WireGuard key), NOT machine key
    memcpy(client_info_frame, ml->wireguard.public_key, 32);
    memcpy(client_info_frame + 32, nonce, NACL_BOX_NONCEBYTES);
    memcpy(client_info_frame + 32 + NACL_BOX_NONCEBYTES, ciphertext, ciphertext_len);

    ESP_LOGI(TAG, "Client info: nodekey(32) + nonce(24) + encrypted_json(%d) = %d bytes",
             (int)ciphertext_len, (int)frame_len);

    // Print FULL 32-byte NodeKey in hex for debug tools
    char nodekey_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&nodekey_hex[i * 2], "%02x", ml->wireguard.public_key[i]);
    }
    ESP_LOGI(TAG, "NodeKey (FULL 32 bytes): %s", nodekey_hex);
    ESP_LOGI(TAG, "NodeKey (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             ml->wireguard.public_key[0], ml->wireguard.public_key[1],
             ml->wireguard.public_key[2], ml->wireguard.public_key[3],
             ml->wireguard.public_key[4], ml->wireguard.public_key[5],
             ml->wireguard.public_key[6], ml->wireguard.public_key[7]);
    ESP_LOGI(TAG, "Nonce (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             nonce[0], nonce[1], nonce[2], nonce[3],
             nonce[4], nonce[5], nonce[6], nonce[7]);
    ESP_LOGI(TAG, "Ciphertext (first 16 = MAC): %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3],
             ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7],
             ciphertext[8], ciphertext[9], ciphertext[10], ciphertext[11],
             ciphertext[12], ciphertext[13], ciphertext[14], ciphertext[15]);
    ESP_LOGI(TAG, "JSON plaintext (%d bytes): %s", (int)json_len, client_info_json);
    ESP_LOGI(TAG, "Our private key (first 8): %02x%02x%02x%02x%02x%02x%02x%02x",
             ml->wireguard.private_key[0], ml->wireguard.private_key[1],
             ml->wireguard.private_key[2], ml->wireguard.private_key[3],
             ml->wireguard.private_key[4], ml->wireguard.private_key[5],
             ml->wireguard.private_key[6], ml->wireguard.private_key[7]);

    err = derp_send_frame(ml, FRAME_CLIENT_INFO, client_info_frame, frame_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send client info");
        return err;
    }

    // Step 3: Receive server info frame (0x03)
    // Format: 24B nonce + naclbox(JSON)
    ESP_LOGI(TAG, "Waiting for server info...");
    err = derp_recv_frame_header(ml, &type, &len, DERP_CONNECT_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to receive server info header");
        return err;
    }

    // Server info frame type is 0x03
    if (type != 0x03) {
        ESP_LOGW(TAG, "Expected SERVER_INFO (0x03), got 0x%02x len=%lu", type, len);
        // Some servers may not send server info, so we continue anyway
        // But we need to read the payload if there is one
        if (len > 0 && len <= sizeof(derp_rx_buffer)) {
            derp_tls_read_all(ml, derp_rx_buffer, len, DERP_CONNECT_TIMEOUT_MS);
        }
    } else {
        // Read and discard server info (we don't need the rate limiting params)
        if (len > 0 && len <= sizeof(derp_rx_buffer)) {
            if (derp_tls_read_all(ml, derp_rx_buffer, len, DERP_CONNECT_TIMEOUT_MS) < 0) {
                ESP_LOGE(TAG, "Failed to read server info");
                return ESP_FAIL;
            }
            ESP_LOGI(TAG, "Received server info (%lu bytes)", len);
        }
    }

    ESP_LOGI(TAG, "DERP handshake complete");
    return ESP_OK;
}

esp_err_t microlink_derp_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing DERP client");

    memset(&ml->derp, 0, sizeof(microlink_derp_t));
    ml->derp.sockfd = -1;

    // Initialize dynamic DERP discovery based on Kconfig
#ifdef CONFIG_MICROLINK_DERP_DYNAMIC_DISCOVERY
    ml->derp.dynamic_discovery_enabled = true;
    ESP_LOGI(TAG, "DERP dynamic discovery: ENABLED (will use DERPMap from server)");
#else
    ml->derp.dynamic_discovery_enabled = false;
    ESP_LOGI(TAG, "DERP dynamic discovery: DISABLED (using hardcoded: %s)",
             MICROLINK_DERP_SERVER);
#endif

    // Initialize mbedTLS RNG (once)
    if (!derp_rng_initialized) {
        mbedtls_entropy_init(&derp_entropy);
        mbedtls_ctr_drbg_init(&derp_ctr_drbg);

        const char *pers = "microlink_derp";
        int ret = mbedtls_ctr_drbg_seed(&derp_ctr_drbg, mbedtls_entropy_func,
                                         &derp_entropy, (const uint8_t *)pers, strlen(pers));
        if (ret != 0) {
            ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: -0x%04x", -ret);
            return ESP_FAIL;
        }
        derp_rng_initialized = true;
    }

    mbedtls_net_init(&derp_server_fd);
    mbedtls_ssl_init(&ml->derp.ssl);
    mbedtls_ssl_config_init(&ml->derp.ssl_conf);
    mbedtls_x509_crt_init(&ml->derp.ca_cert);

    ESP_LOGI(TAG, "DERP client initialized");
    return ESP_OK;
}

esp_err_t microlink_derp_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing DERP client");

    if (ml->derp.connected) {
        mbedtls_ssl_close_notify(&ml->derp.ssl);
    }

    mbedtls_ssl_free(&ml->derp.ssl);
    mbedtls_ssl_config_free(&ml->derp.ssl_conf);
    mbedtls_x509_crt_free(&ml->derp.ca_cert);
    mbedtls_net_free(&derp_server_fd);

    if (ml->derp.sockfd >= 0) {
        close(ml->derp.sockfd);
    }

    memset(&ml->derp, 0, sizeof(microlink_derp_t));
    ml->derp.sockfd = -1;

    return ESP_OK;
}

static esp_err_t derp_connect_once(microlink_t *ml);

/* Current DERP port (may be overridden by dynamic discovery) */
static uint16_t current_derp_port = MICROLINK_DERP_PORT;

esp_err_t microlink_derp_connect(microlink_t *ml) {
    // ========================================================================
    // DERP Server Selection Strategy:
    // 1. If dynamic discovery is enabled AND regions were discovered from DERPMap,
    //    use the discovered regions in order.
    // 2. Otherwise, use the hardcoded MICROLINK_DERP_SERVER and fallback.
    //
    // This allows users to:
    // - Use hardcoded servers for self-hosted DERP or deterministic selection
    // - Use dynamic discovery when tailnet has custom derpMap configurations
    // ========================================================================

#ifdef CONFIG_MICROLINK_DERP_DYNAMIC_DISCOVERY
    // Dynamic discovery mode: use regions from DERPMap if available
    if (ml->derp.dynamic_discovery_enabled && ml->derp.region_count > 0) {
        ESP_LOGI(TAG, "DERP: Using dynamic discovery (%d regions available)",
                 ml->derp.region_count);

        // First, try to find and connect to the preferred region (from Kconfig)
        int preferred_region_id = MICROLINK_DERP_REGION;
        int preferred_idx = -1;
        for (int i = 0; i < ml->derp.region_count; i++) {
            if (ml->derp.regions[i].region_id == preferred_region_id) {
                preferred_idx = i;
                break;
            }
        }

        if (preferred_idx >= 0) {
            ESP_LOGI(TAG, "DERP: Found preferred region %d in discovered list", preferred_region_id);
        } else {
            ESP_LOGW(TAG, "DERP: Preferred region %d not in discovered list, will try others", preferred_region_id);
        }

        // Build connection order: preferred first, then others
        int connection_order[MICROLINK_MAX_DERP_REGIONS];
        int order_count = 0;

        // Add preferred region first if found
        if (preferred_idx >= 0) {
            connection_order[order_count++] = preferred_idx;
        }

        // Add remaining regions
        for (int i = 0; i < ml->derp.region_count; i++) {
            if (i != preferred_idx) {
                connection_order[order_count++] = i;
            }
        }

        for (int order_idx = 0; order_idx < order_count; order_idx++) {
            int region_idx = connection_order[order_idx];
            microlink_derp_region_t *region = &ml->derp.regions[region_idx];
            current_derp_server = region->hostname;
            current_derp_port = region->port;

            // Retry each region up to 2 times
            for (int attempt = 1; attempt <= 2; attempt++) {
                ESP_LOGI(TAG, "DERP connect: region=%d server=%s:%d attempt=%d",
                         region->region_id, current_derp_server, current_derp_port, attempt);

                esp_err_t err = derp_connect_once(ml);
                if (err == ESP_OK) {
                    ml->derp.current_region_idx = region_idx;
                    ESP_LOGI(TAG, "DERP: Connected to region %d (%s)",
                             region->region_id, current_derp_server);
                    return ESP_OK;
                }

                // Cleanup for retry
                mbedtls_ssl_close_notify(&ml->derp.ssl);
                mbedtls_ssl_free(&ml->derp.ssl);
                mbedtls_ssl_config_free(&ml->derp.ssl_conf);
                mbedtls_net_free(&derp_server_fd);
                ml->derp.sockfd = -1;

                mbedtls_net_init(&derp_server_fd);
                mbedtls_ssl_init(&ml->derp.ssl);
                mbedtls_ssl_config_init(&ml->derp.ssl_conf);

                if (attempt < 2) {
                    ESP_LOGW(TAG, "DERP attempt %d to region %d failed, retrying...",
                             attempt, region->region_id);
                    vTaskDelay(pdMS_TO_TICKS(2000));
                }
            }

            ESP_LOGW(TAG, "DERP: Region %d (%s) failed, trying next region",
                     region->region_id, current_derp_server);
        }

        ESP_LOGE(TAG, "DERP: All %d discovered regions failed", ml->derp.region_count);
        return ESP_FAIL;
    }
#endif  // CONFIG_MICROLINK_DERP_DYNAMIC_DISCOVERY

    // Hardcoded mode (default): use configured servers
    ESP_LOGI(TAG, "DERP: Using hardcoded servers");
    const char *servers[] = {MICROLINK_DERP_SERVER, MICROLINK_DERP_SERVER_FALLBACK};
    current_derp_port = MICROLINK_DERP_PORT;

    for (int server_idx = 0; server_idx < 2; server_idx++) {
        current_derp_server = servers[server_idx];

        // Retry each server up to 2 times with backoff
        for (int attempt = 1; attempt <= 2; attempt++) {
            ESP_LOGI(TAG, "DERP connect: server=%s attempt=%d",
                     current_derp_server, attempt);

            esp_err_t err = derp_connect_once(ml);
            if (err == ESP_OK) {
                return ESP_OK;
            }

            // Full cleanup - free SSL and socket resources completely
            mbedtls_ssl_close_notify(&ml->derp.ssl);
            mbedtls_ssl_free(&ml->derp.ssl);
            mbedtls_ssl_config_free(&ml->derp.ssl_conf);
            mbedtls_net_free(&derp_server_fd);
            ml->derp.sockfd = -1;

            // Re-initialize ALL structures for next attempt (including net context!)
            mbedtls_net_init(&derp_server_fd);
            mbedtls_ssl_init(&ml->derp.ssl);
            mbedtls_ssl_config_init(&ml->derp.ssl_conf);

            if (attempt < 2) {
                ESP_LOGW(TAG, "DERP connect attempt %d to %s failed, retrying...",
                         attempt, current_derp_server);
                vTaskDelay(pdMS_TO_TICKS(2000));
            }
        }

        if (server_idx < 1) {
            ESP_LOGW(TAG, "Failed to connect to %s, trying fallback %s",
                     servers[server_idx], servers[server_idx + 1]);
        }
    }

    ESP_LOGE(TAG, "DERP connection failed after trying all servers");
    return ESP_FAIL;
}

static esp_err_t derp_connect_once(microlink_t *ml) {
    int ret;
    char port_str[8];

    ESP_LOGI(TAG, "Connecting to DERP relay: %s:%d",
             current_derp_server, current_derp_port);

    snprintf(port_str, sizeof(port_str), "%d", current_derp_port);

    // Step 1: TCP connection
    ESP_LOGI(TAG, "Establishing TCP connection...");
    uint64_t tcp_start = microlink_get_time_ms();
    ret = mbedtls_net_connect(&derp_server_fd, current_derp_server, port_str, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        ESP_LOGE(TAG, "TCP connect failed: -0x%04x", -ret);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "TCP connected in %lu ms (fd=%d)",
             (unsigned long)(microlink_get_time_ms() - tcp_start), derp_server_fd.fd);
    ml->derp.sockfd = derp_server_fd.fd;

    // Set socket timeouts for TLS handshake
    struct timeval tv;
    tv.tv_sec = 10;  // 10 second timeout
    tv.tv_usec = 0;
    setsockopt(derp_server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(derp_server_fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Step 2: Configure TLS
    ESP_LOGI(TAG, "Configuring TLS...");
    ret = mbedtls_ssl_config_defaults(&ml->derp.ssl_conf,
                                       MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        ESP_LOGE(TAG, "ssl_config_defaults failed: -0x%04x", -ret);
        goto fail;
    }

    // Skip certificate verification for now (tailscale uses valid certs)
    mbedtls_ssl_conf_authmode(&ml->derp.ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&ml->derp.ssl_conf, mbedtls_ctr_drbg_random, &derp_ctr_drbg);

    ret = mbedtls_ssl_setup(&ml->derp.ssl, &ml->derp.ssl_conf);
    if (ret != 0) {
        ESP_LOGE(TAG, "ssl_setup failed: -0x%04x", -ret);
        goto fail;
    }

    ret = mbedtls_ssl_set_hostname(&ml->derp.ssl, current_derp_server);
    if (ret != 0) {
        ESP_LOGE(TAG, "ssl_set_hostname failed: -0x%04x", -ret);
        goto fail;
    }

    mbedtls_ssl_set_bio(&ml->derp.ssl, &derp_server_fd,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    // Step 3: TLS handshake
    ESP_LOGI(TAG, "Performing TLS handshake...");
    uint64_t tls_start = microlink_get_time_ms();
    while ((ret = mbedtls_ssl_handshake(&ml->derp.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "TLS handshake failed: -0x%04x", -ret);
            goto fail;
        }
    }
    ESP_LOGI(TAG, "TLS handshake complete in %lu ms, cipher: %s",
             (unsigned long)(microlink_get_time_ms() - tls_start),
             mbedtls_ssl_get_ciphersuite(&ml->derp.ssl));

    // Step 4: HTTP upgrade to DERP
    esp_err_t err = derp_send_http_upgrade(ml);
    if (err != ESP_OK) {
        goto fail;
    }

    // Step 5: DERP protocol handshake
    err = derp_handshake(ml);
    if (err != ESP_OK) {
        goto fail;
    }

    ml->derp.connected = true;
    ml->derp.last_keepalive_ms = microlink_get_time_ms();

    // CRITICAL: Set socket to non-blocking mode for TLS operations
    // This makes mbedtls return WANT_READ/WANT_WRITE instead of blocking forever
    int ret_nb = mbedtls_net_set_nonblock(&derp_server_fd);
    if (ret_nb != 0) {
        ESP_LOGW(TAG, "Failed to set non-blocking mode: -0x%04x (continuing anyway)", -ret_nb);
    } else {
        ESP_LOGI(TAG, "Set DERP socket to non-blocking mode");
    }

    // Also set short socket timeouts as fallback
    struct timeval tv_short;
    tv_short.tv_sec = 0;
    tv_short.tv_usec = 100 * 1000;  // 100ms timeout for polling
    setsockopt(ml->derp.sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_short, sizeof(tv_short));
    setsockopt(ml->derp.sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv_short, sizeof(tv_short));
    ESP_LOGI(TAG, "Set DERP socket send/receive timeout to 100ms");

    // CRITICAL: Send NotePreferred IMMEDIATELY after connecting
    // This tells the DERP server to route packets to us right away
    // Without this, other peers can't reach us via DERP until the first keepalive
    ESP_LOGI(TAG, "Sending NotePreferred=true to mark this as our home DERP");
    uint8_t preferred = 0x01;
    derp_send_frame(ml, FRAME_NOTE_PREFERRED, &preferred, 1);

    ESP_LOGI(TAG, "DERP relay connected successfully");
    return ESP_OK;

fail:
    mbedtls_ssl_close_notify(&ml->derp.ssl);
    mbedtls_net_free(&derp_server_fd);
    ml->derp.sockfd = -1;
    return ESP_FAIL;
}

esp_err_t microlink_derp_reconnect(microlink_t *ml) {
    ESP_LOGI(TAG, "Reconnecting DERP relay (coordination session refreshed)...");

    // Close existing connection if any
    if (ml->derp.connected) {
        ESP_LOGI(TAG, "Closing stale DERP connection");
        mbedtls_ssl_close_notify(&ml->derp.ssl);
        ml->derp.connected = false;
    }

    // Free ALL SSL resources completely
    mbedtls_ssl_free(&ml->derp.ssl);
    mbedtls_ssl_config_free(&ml->derp.ssl_conf);
    mbedtls_net_free(&derp_server_fd);
    ml->derp.sockfd = -1;

    // Re-setup SSL context (needed for new connection)
    mbedtls_net_init(&derp_server_fd);
    mbedtls_ssl_init(&ml->derp.ssl);
    mbedtls_ssl_config_init(&ml->derp.ssl_conf);

    // Small delay to let server-side cleanup
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Reconnect
    return microlink_derp_connect(ml);
}

esp_err_t microlink_derp_send(microlink_t *ml, uint32_t dest_vpn_ip,
                              const uint8_t *data, size_t len) {
    if (!ml->derp.connected) {
        return ESP_ERR_INVALID_STATE;
    }

    // Find peer by VPN IP to get their public key
    uint8_t peer_idx = microlink_peer_find_by_vpn_ip(ml, dest_vpn_ip);
    if (peer_idx >= ml->peer_count) {
        ESP_LOGW(TAG, "Peer not found for VPN IP");
        return ESP_ERR_NOT_FOUND;
    }

    const microlink_peer_t *peer = &ml->peers[peer_idx];

    // Delegate to raw send function
    return microlink_derp_send_raw(ml, peer->public_key, data, len);
}

esp_err_t microlink_derp_send_raw(microlink_t *ml, const uint8_t *dest_pubkey,
                                   const uint8_t *data, size_t len) {
    if (!ml->derp.connected) {
        ESP_LOGW(TAG, "DERP not connected, cannot send WG packet");
        return ESP_ERR_INVALID_STATE;
    }

    if (len > MICROLINK_NETWORK_BUFFER_SIZE) {
        ESP_LOGE(TAG, "Packet too large: %u", (unsigned int)len);
        return ESP_ERR_INVALID_SIZE;
    }

    // Build SEND_PACKET frame: [32-byte dest public key][payload]
    // Use heap allocation to avoid stack overflow when called from WireGuard timer task
    size_t frame_len = 32 + len;
    uint8_t *frame = (uint8_t *)malloc(frame_len);
    if (!frame) {
        ESP_LOGE(TAG, "Failed to allocate DERP frame buffer");
        return ESP_ERR_NO_MEM;
    }

    memcpy(frame, dest_pubkey, 32);
    memcpy(frame + 32, data, len);

    ESP_LOGI(TAG, "DERP SEND_PACKET: %u bytes to peer %02x%02x%02x%02x%02x%02x%02x%02x...",
             (unsigned int)len, dest_pubkey[0], dest_pubkey[1], dest_pubkey[2], dest_pubkey[3],
             dest_pubkey[4], dest_pubkey[5], dest_pubkey[6], dest_pubkey[7]);

    // Check if this is a DISCO packet
    if (len >= 6 && memcmp(data, "TS\xf0\x9f\x92\xac", 6) == 0) {
        ESP_LOGI(TAG, "  >> DISCO packet detected in DERP send!");
        if (len >= 38) {
            ESP_LOGI(TAG, "  Sender disco_key in packet: %02x%02x%02x%02x%02x%02x%02x%02x...",
                     data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13]);
        }
    }

    esp_err_t err = derp_send_frame(ml, FRAME_SEND_PACKET, frame, frame_len);
    if (err == ESP_OK) {
        ml->stats.derp_packets_relayed++;
        ESP_LOGI(TAG, "  DERP frame sent successfully");
    } else {
        ESP_LOGE(TAG, "  DERP frame send FAILED: %s", esp_err_to_name(err));
    }

    free(frame);
    return err;
}

esp_err_t microlink_derp_receive(microlink_t *ml) {
    static uint32_t recv_call_count = 0;
    static uint64_t last_recv_debug = 0;

    if (!ml->derp.connected) {
        return ESP_ERR_INVALID_STATE;
    }

    recv_call_count++;

    // Send NotePreferred periodically to keep connection alive
    // This tells the server we're still here and this is our preferred DERP
    uint64_t now = microlink_get_time_ms();
    if (now - ml->derp.last_keepalive_ms > DERP_KEEPALIVE_MS) {
        ESP_LOGI(TAG, "Sending DERP NotePreferred keepalive (calls=%lu)", (unsigned long)recv_call_count);
        // NotePreferred frame: 1 byte bool (0x01 = preferred)
        uint8_t preferred = 0x01;
        derp_send_frame(ml, FRAME_NOTE_PREFERRED, &preferred, 1);
        ml->derp.last_keepalive_ms = now;
    }

    // Debug log every 10 seconds to show we're polling
    if (now - last_recv_debug >= 10000) {
        ESP_LOGI(TAG, "DERP receive polling: calls=%lu, connected=%d, sockfd=%d",
                 (unsigned long)recv_call_count, ml->derp.connected, ml->derp.sockfd);
        last_recv_debug = now;
    }

    // Initialize mutex if needed (same mutex as send uses)
    if (derp_tls_mutex == NULL) {
        derp_tls_mutex = xSemaphoreCreateMutexStatic(&derp_tls_mutex_buffer);
        if (derp_tls_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create DERP TLS mutex in receive");
            return ESP_FAIL;
        }
    }

    // Take mutex for TLS read operations - use short timeout
    // If send is in progress, skip this receive cycle
    if (xSemaphoreTake(derp_tls_mutex, pdMS_TO_TICKS(10)) != pdTRUE) {
        // Send is in progress, skip receive this cycle
        return ESP_OK;
    }

    // Try to read a frame (non-blocking with short timeout)
    uint8_t type;
    uint32_t len;
    esp_err_t err = derp_recv_frame_header(ml, &type, &len, DERP_READ_TIMEOUT_MS);
    if (err == ESP_ERR_TIMEOUT) {
        xSemaphoreGive(derp_tls_mutex);
        return ESP_OK;  // No data available
    }
    if (err != ESP_OK) {
        xSemaphoreGive(derp_tls_mutex);
        ESP_LOGE(TAG, "DERP connection lost (err=%d)", err);
        ml->derp.connected = false;
        return ESP_FAIL;
    }

    // Sanity check frame length
    if (len > DERP_MAX_FRAME_SIZE) {
        xSemaphoreGive(derp_tls_mutex);
        ESP_LOGE(TAG, "Frame too large: %lu", len);
        ml->derp.connected = false;
        return ESP_FAIL;
    }

    // Read frame payload
    if (len > 0) {
        if (derp_tls_read_all(ml, derp_rx_buffer, len, DERP_CONNECT_TIMEOUT_MS) < 0) {
            xSemaphoreGive(derp_tls_mutex);
            ESP_LOGE(TAG, "Failed to read frame payload");
            ml->derp.connected = false;
            return ESP_FAIL;
        }
    }

    // Release mutex - we've read all the data we need
    xSemaphoreGive(derp_tls_mutex);

    // Log ALL incoming frames for debugging
    ESP_LOGI(TAG, "DERP frame received: type=0x%02x len=%lu", type, (unsigned long)len);

    // Handle frame by type
    switch (type) {
        case FRAME_RECV_PACKET: {
            // Format: [32-byte source public key][payload]
            if (len < 32) {
                ESP_LOGW(TAG, "RECV_PACKET too short");
                break;
            }

            uint8_t *src_key = derp_rx_buffer;
            uint8_t *payload = derp_rx_buffer + 32;
            size_t payload_len = len - 32;

            // Check if this is a DISCO packet (starts with "TS💬" magic)
            // DISCO packets must be routed to the DISCO handler, NOT WireGuard
            if (microlink_disco_is_disco_packet(payload, payload_len)) {
                ESP_LOGI(TAG, "Received DISCO packet via DERP (%u bytes)", (unsigned int)payload_len);
                microlink_disco_handle_derp_packet(ml, src_key, payload, payload_len);
                break;
            }

            // Identify WireGuard message type first
            uint8_t wg_type = (payload_len >= 1) ? payload[0] : 0;
            const char *wg_type_str = "UNKNOWN";
            if (wg_type == 1) wg_type_str = "HANDSHAKE_INIT";
            else if (wg_type == 2) wg_type_str = "HANDSHAKE_RESP";
            else if (wg_type == 3) wg_type_str = "COOKIE";
            else if (wg_type == 4) wg_type_str = "TRANSPORT";

            ESP_LOGI(TAG, "Received WG packet via DERP: %u bytes, type=%s from %02x%02x%02x%02x...",
                     (unsigned int)payload_len, wg_type_str, src_key[0], src_key[1], src_key[2], src_key[3]);

            // Find peer by public key to get VPN IP (optional for handshakes)
            uint32_t src_vpn_ip = 0;
            for (int i = 0; i < ml->peer_count; i++) {
                if (memcmp(ml->peers[i].public_key, src_key, 32) == 0) {
                    src_vpn_ip = ml->peers[i].vpn_ip;
                    ESP_LOGI(TAG, "  -> Matched peer %d, VPN IP: %d.%d.%d.%d",
                             i, (src_vpn_ip >> 24) & 0xFF, (src_vpn_ip >> 16) & 0xFF,
                             (src_vpn_ip >> 8) & 0xFF, src_vpn_ip & 0xFF);
                    break;
                }
            }

            if (src_vpn_ip == 0) {
                // Unknown peer - for handshake initiations, we should still process
                // The WireGuard stack will validate the handshake cryptographically
                ESP_LOGW(TAG, "Received packet from unknown peer (pubkey not in peer list)");
                // Use a dummy VPN IP for unknown peers - WG stack identifies by sender index
                // For handshakes, the real identity comes from the encrypted payload
                src_vpn_ip = 0x64400001;  // 100.64.0.1 - placeholder
            }

            // CRITICAL: Inject WireGuard packets DIRECTLY into the WG stack
            // This is essential for handshake processing - don't just queue them!
            // Handshake responses need immediate processing or they'll timeout.
            esp_err_t inject_err = microlink_wireguard_inject_derp_packet(ml, src_vpn_ip,
                                                                           payload, payload_len);
            if (inject_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to inject DERP packet into WireGuard: %d", inject_err);
            }
            break;
        }

        case FRAME_PING:
            // Server ping - must respond with PONG echoing the 8-byte data
            // This is CRITICAL for keeping the connection alive!
            if (len == 8) {
                ESP_LOGD(TAG, "Ping from server, sending pong");
                derp_send_frame(ml, FRAME_PONG, derp_rx_buffer, 8);
            } else {
                ESP_LOGW(TAG, "Ping with unexpected length: %lu", len);
                // Still try to respond with whatever we got
                derp_send_frame(ml, FRAME_PONG, derp_rx_buffer, len);
            }
            break;

        case FRAME_KEEP_ALIVE:
            // Keep-alive is informational, no response needed
            ESP_LOGD(TAG, "Keep-alive from server");
            break;

        case FRAME_PEER_PRESENT:
            if (len >= 32) {
                ESP_LOGI(TAG, "Peer PRESENT on DERP: %02x%02x%02x%02x...",
                         derp_rx_buffer[0], derp_rx_buffer[1],
                         derp_rx_buffer[2], derp_rx_buffer[3]);
            }
            break;

        case FRAME_PEER_GONE:
            if (len >= 32) {
                ESP_LOGI(TAG, "Peer GONE from DERP: %02x%02x%02x%02x...",
                         derp_rx_buffer[0], derp_rx_buffer[1],
                         derp_rx_buffer[2], derp_rx_buffer[3]);
            }
            break;

        case FRAME_SERVER_INFO:
            ESP_LOGD(TAG, "Server info received (%lu bytes)", len);
            break;

        case FRAME_SERVER_RESTART:
            // Server will restart soon, prepare for reconnection
            ESP_LOGW(TAG, "Server restart imminent!");
            break;

        case FRAME_HEALTH:
            ESP_LOGD(TAG, "Health check from server");
            break;

        default:
            ESP_LOGD(TAG, "Unknown frame type: 0x%02x len=%lu", type, len);
            break;
    }

    return ESP_OK;
}

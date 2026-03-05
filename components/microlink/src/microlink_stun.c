/**
 * @file microlink_stun.c
 * @brief STUN client for NAT discovery (RFC 5389/8489)
 *
 * Discovers public IP and port mapping using STUN protocol.
 * Used by Tailscale for NAT traversal and direct peer connections.
 *
 * STUN message format:
 *   [2B type][2B length][4B magic cookie 0x2112A442][12B transaction ID]
 *   [attributes...]
 *
 * Binding Request: type 0x0001, no attributes needed
 * Binding Response: type 0x0101, contains XOR-MAPPED-ADDRESS (0x0020)
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <lwip/sockets.h>
#include <errno.h>

static const char *TAG = "ml_stun";

/* STUN protocol constants (RFC 5389) */
#define STUN_MAGIC_COOKIE       0x2112A442
#define STUN_HEADER_SIZE        20
#define STUN_TRANSACTION_ID_LEN 12

/* STUN message types */
#define STUN_BINDING_REQUEST    0x0001
#define STUN_BINDING_RESPONSE   0x0101
#define STUN_BINDING_ERROR      0x0111

/* STUN attribute types */
#define STUN_ATTR_MAPPED_ADDRESS        0x0001  // RFC 3489 (deprecated)
#define STUN_ATTR_XOR_MAPPED_ADDRESS    0x0020  // RFC 5389

/* Address family */
#define STUN_ADDR_FAMILY_IPV4   0x01
#define STUN_ADDR_FAMILY_IPV6   0x02

/* Timeouts */
#define STUN_TIMEOUT_MS         6000
#define STUN_RETRY_COUNT        3

/* Static transaction ID storage */
static uint8_t stun_transaction_id[STUN_TRANSACTION_ID_LEN];

/**
 * @brief Build a STUN Binding Request
 */
static size_t stun_build_binding_request(uint8_t *buf, size_t buf_size) {
    if (buf_size < STUN_HEADER_SIZE) {
        return 0;
    }

    // Message Type: Binding Request (0x0001)
    buf[0] = 0x00;
    buf[1] = 0x01;

    // Message Length: 0 (no attributes)
    buf[2] = 0x00;
    buf[3] = 0x00;

    // Magic Cookie: 0x2112A442 (big-endian)
    buf[4] = 0x21;
    buf[5] = 0x12;
    buf[6] = 0xA4;
    buf[7] = 0x42;

    // Transaction ID: 12 random bytes
    // Use simple PRNG for transaction ID (esp_random)
    uint32_t r = esp_random();
    for (int i = 0; i < STUN_TRANSACTION_ID_LEN; i++) {
        if (i % 4 == 0 && i > 0) {
            r = esp_random();
        }
        stun_transaction_id[i] = (r >> ((i % 4) * 8)) & 0xFF;
        buf[8 + i] = stun_transaction_id[i];
    }

    return STUN_HEADER_SIZE;
}

/**
 * @brief Parse STUN Binding Response
 * @return 0 on success, -1 on error
 */
static int stun_parse_binding_response(const uint8_t *buf, size_t len,
                                        uint32_t *mapped_ip, uint16_t *mapped_port) {
    if (len < STUN_HEADER_SIZE) {
        ESP_LOGE(TAG, "Response too short: %u bytes", (unsigned int)len);
        return -1;
    }

    // Check message type (Binding Response: 0x0101)
    uint16_t msg_type = ((uint16_t)buf[0] << 8) | buf[1];
    if (msg_type != STUN_BINDING_RESPONSE) {
        ESP_LOGE(TAG, "Unexpected message type: 0x%04x", msg_type);
        return -1;
    }

    // Get message length
    uint16_t msg_len = ((uint16_t)buf[2] << 8) | buf[3];
    if (STUN_HEADER_SIZE + msg_len > len) {
        ESP_LOGE(TAG, "Message truncated: claimed %u, have %u", msg_len, (unsigned int)(len - STUN_HEADER_SIZE));
        return -1;
    }

    // Verify magic cookie
    uint32_t cookie = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                      ((uint32_t)buf[6] << 8) | buf[7];
    if (cookie != STUN_MAGIC_COOKIE) {
        ESP_LOGE(TAG, "Invalid magic cookie: 0x%08lx", (unsigned long)cookie);
        return -1;
    }

    // Verify transaction ID
    if (memcmp(buf + 8, stun_transaction_id, STUN_TRANSACTION_ID_LEN) != 0) {
        ESP_LOGE(TAG, "Transaction ID mismatch");
        return -1;
    }

    // Parse attributes
    const uint8_t *ptr = buf + STUN_HEADER_SIZE;
    const uint8_t *end = buf + STUN_HEADER_SIZE + msg_len;

    while (ptr + 4 <= end) {
        uint16_t attr_type = ((uint16_t)ptr[0] << 8) | ptr[1];
        uint16_t attr_len = ((uint16_t)ptr[2] << 8) | ptr[3];
        ptr += 4;

        if (ptr + attr_len > end) {
            ESP_LOGE(TAG, "Attribute truncated");
            return -1;
        }

        ESP_LOGD(TAG, "Attribute: type=0x%04x len=%u", attr_type, attr_len);

        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8) {
            // XOR-MAPPED-ADDRESS format:
            // [1B reserved][1B family][2B X-Port][4B X-Address (for IPv4)]
            uint8_t family = ptr[1];

            if (family == STUN_ADDR_FAMILY_IPV4) {
                // X-Port = port XOR (magic cookie >> 16)
                uint16_t x_port = ((uint16_t)ptr[2] << 8) | ptr[3];
                *mapped_port = x_port ^ (STUN_MAGIC_COOKIE >> 16);

                // X-Address = address XOR magic cookie
                uint32_t x_addr = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                                  ((uint32_t)ptr[6] << 8) | ptr[7];
                *mapped_ip = x_addr ^ STUN_MAGIC_COOKIE;

                ESP_LOGI(TAG, "XOR-MAPPED-ADDRESS: %lu.%lu.%lu.%lu:%u",
                         (*mapped_ip >> 24) & 0xFF,
                         (*mapped_ip >> 16) & 0xFF,
                         (*mapped_ip >> 8) & 0xFF,
                         *mapped_ip & 0xFF,
                         *mapped_port);
                return 0;
            } else {
                ESP_LOGW(TAG, "IPv6 not supported, family=%u", family);
            }
        } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && attr_len >= 8) {
            // Fallback: MAPPED-ADDRESS (RFC 3489, not XORed)
            // Some servers still include this for backwards compatibility
            uint8_t family = ptr[1];

            if (family == STUN_ADDR_FAMILY_IPV4) {
                *mapped_port = ((uint16_t)ptr[2] << 8) | ptr[3];
                *mapped_ip = ((uint32_t)ptr[4] << 24) | ((uint32_t)ptr[5] << 16) |
                             ((uint32_t)ptr[6] << 8) | ptr[7];

                ESP_LOGI(TAG, "MAPPED-ADDRESS: %lu.%lu.%lu.%lu:%u",
                         (*mapped_ip >> 24) & 0xFF,
                         (*mapped_ip >> 16) & 0xFF,
                         (*mapped_ip >> 8) & 0xFF,
                         *mapped_ip & 0xFF,
                         *mapped_port);
                return 0;
            }
        }

        // Move to next attribute (aligned to 4 bytes)
        size_t padded_len = (attr_len + 3) & ~3;
        ptr += padded_len;
    }

    ESP_LOGE(TAG, "No MAPPED-ADDRESS attribute found");
    return -1;
}

esp_err_t microlink_stun_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing STUN client");

    memset(&ml->stun, 0, sizeof(microlink_stun_t));
    ml->stun.sock_fd = -1;

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create UDP socket: %d", errno);
        return ESP_FAIL;
    }

    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = STUN_TIMEOUT_MS / 1000;
    tv.tv_usec = (STUN_TIMEOUT_MS % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ml->stun.sock_fd = sock;

    ESP_LOGI(TAG, "STUN client initialized, socket=%d", sock);
    return ESP_OK;
}

esp_err_t microlink_stun_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing STUN client");

    if (ml->stun.sock_fd >= 0) {
        close(ml->stun.sock_fd);
        ml->stun.sock_fd = -1;
    }

    memset(&ml->stun, 0, sizeof(microlink_stun_t));
    return ESP_OK;
}

/**
 * @brief Try STUN probe to a specific server
 * @return ESP_OK on success, ESP_FAIL on failure
 */
static esp_err_t stun_probe_server(microlink_t *ml, const char *server, uint16_t port) {
    ESP_LOGI(TAG, "Trying STUN server %s:%d", server, port);

    // Resolve STUN server hostname
    struct hostent *he = gethostbyname(server);
    if (he == NULL) {
        ESP_LOGW(TAG, "Failed to resolve %s", server);
        return ESP_FAIL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], sizeof(server_addr.sin_addr));

    ESP_LOGD(TAG, "STUN server IP: %s", inet_ntoa(*(struct in_addr *)he->h_addr_list[0]));

    // Build STUN Binding Request
    uint8_t request[STUN_HEADER_SIZE];
    size_t req_len = stun_build_binding_request(request, sizeof(request));
    if (req_len == 0) {
        ESP_LOGE(TAG, "Failed to build STUN request");
        return ESP_FAIL;
    }

    // Retry loop
    uint8_t response[256];
    int retries = STUN_RETRY_COUNT;

    while (retries > 0) {
        // Send request
        ssize_t sent = sendto(ml->stun.sock_fd, request, req_len, 0,
                              (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent < 0) {
            ESP_LOGE(TAG, "Failed to send STUN request: %d", errno);
            retries--;
            continue;
        }

        ESP_LOGD(TAG, "Sent STUN Binding Request (%zd bytes)", sent);

        // Receive response
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        ssize_t recv_len = recvfrom(ml->stun.sock_fd, response, sizeof(response), 0,
                                    (struct sockaddr *)&from_addr, &from_len);

        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ESP_LOGW(TAG, "STUN timeout, retrying (%d left)", retries - 1);
                retries--;
                continue;
            }
            ESP_LOGE(TAG, "Failed to receive STUN response: %d", errno);
            retries--;
            continue;
        }

        ESP_LOGD(TAG, "Received STUN response (%zd bytes)", recv_len);

        // Parse response
        uint32_t mapped_ip = 0;
        uint16_t mapped_port = 0;

        if (stun_parse_binding_response(response, recv_len, &mapped_ip, &mapped_port) == 0) {
            // Success!
            ml->stun.public_ip = mapped_ip;
            ml->stun.public_port = mapped_port;
            ml->stun.nat_detected = true;
            ml->stun.last_probe_ms = microlink_get_time_ms();

            ESP_LOGI(TAG, "STUN probe successful: public endpoint %lu.%lu.%lu.%lu:%u",
                     (mapped_ip >> 24) & 0xFF,
                     (mapped_ip >> 16) & 0xFF,
                     (mapped_ip >> 8) & 0xFF,
                     mapped_ip & 0xFF,
                     mapped_port);

            return ESP_OK;
        }

        retries--;
    }

    return ESP_FAIL;
}

esp_err_t microlink_stun_probe(microlink_t *ml) {
    if (ml->stun.sock_fd < 0) {
        ESP_LOGE(TAG, "STUN socket not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    // Try primary STUN server first (Tailscale)
    if (stun_probe_server(ml, MICROLINK_STUN_SERVER, MICROLINK_STUN_PORT) == ESP_OK) {
        return ESP_OK;
    }

    // Try fallback server (Google)
    ESP_LOGW(TAG, "Primary STUN server failed, trying fallback...");
    if (stun_probe_server(ml, MICROLINK_STUN_SERVER_FALLBACK, MICROLINK_STUN_PORT_GOOGLE) == ESP_OK) {
        return ESP_OK;
    }

    ESP_LOGE(TAG, "All STUN servers failed");
    return ESP_FAIL;
}

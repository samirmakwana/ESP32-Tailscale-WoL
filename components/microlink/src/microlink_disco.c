/**
 * @file microlink_disco.c
 * @brief DISCO protocol for path discovery and optimization
 *
 * Tests multiple network paths and selects the best one based on latency.
 *
 * DISCO packets are sent via WireGuard tunnel or DERP relay and contain:
 * - 6-byte magic: "TS💬" (DISCO magic)
 * - 32-byte sender disco public key
 * - 24-byte nonce
 * - Encrypted payload (NaCl box):
 *   - 1-byte message type (ping=0x01, pong=0x02, call_me_maybe=0x03)
 *   - 12-byte TxID (for ping/pong matching)
 *   - Additional data depending on type
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"  // For getting local WiFi IP
#include "nacl_box.h"
#include <string.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/err.h>
#include <lwip/netif.h>

static const char *TAG = "ml_disco";

/* DISCO protocol constants */
#define DISCO_MAGIC             "TS\xf0\x9f\x92\xac"  // "TS💬" (6 bytes)
#define DISCO_MAGIC_LEN         6
#define DISCO_KEY_LEN           32
#define DISCO_NONCE_LEN         24
#define DISCO_TXID_LEN          12
#define DISCO_MAC_LEN           16

/* Message types (encrypted payload) */
#define DISCO_MSG_PING          0x01
#define DISCO_MSG_PONG          0x02
#define DISCO_MSG_CALL_ME_MAYBE 0x03

/* Timing - adaptive intervals based on path state (from dj-oyu fork) */
#define DISCO_PROBE_INTERVAL_SEARCH_MS  5000   // 5 seconds when searching for direct path (using_derp=true)
#define DISCO_PROBE_INTERVAL_DIRECT_MS  30000  // 30 seconds when direct path established
#define DISCO_PROBE_TIMEOUT_MS          5000   // 5 second timeout for response
#define DISCO_STALE_THRESHOLD_MS        60000  // Consider path stale after 60s
#define DISCO_PONG_RATE_LIMIT_MS        5000   // Rate-limit PONGs to 1/5s per peer when direct path established (from dj-oyu fork)

/* Maximum DISCO packet size */
#define DISCO_MAX_PACKET_SIZE   256

/* Per-endpoint probe state */
typedef struct {
    uint8_t txid[DISCO_TXID_LEN];   // Transaction ID
    uint64_t send_time_ms;           // When probe was sent
    bool pending;                    // Waiting for response
} disco_probe_state_t;

/* Pending probes for each peer/endpoint combination */
static disco_probe_state_t pending_probes[MICROLINK_MAX_PEERS][MICROLINK_MAX_ENDPOINTS];

/* UDP socket for direct DISCO probes */
static int disco_socket = -1;

/* ============================================================================
 * High-Priority DISCO Receive Task (PC-like responsiveness fix)
 * ============================================================================
 * The main loop may only call microlink_update() every 10-50ms, which causes
 * inconsistent ping responses compared to PC Tailscale (which runs as a daemon
 * with dedicated threads).
 *
 * Solution: A dedicated high-priority task polls the DISCO socket every 5ms
 * and responds to PINGs immediately. This achieves PC-like PONG consistency.
 * ========================================================================== */
#define DISCO_TASK_STACK_SIZE   (4 * 1024)
#define DISCO_TASK_PRIORITY     5  // Medium priority (must be lower than IDLE watchdog threshold)
#define DISCO_POLL_INTERVAL_MS  20  // 20ms = 50Hz polling (was 10ms/100Hz) - reduces CPU while still fast

static TaskHandle_t disco_task_handle = NULL;
static volatile bool disco_task_running = false;
static microlink_t *disco_task_ml = NULL;  // Context for the DISCO task

/* Forward declarations */
static esp_err_t disco_probe_via_derp(microlink_t *ml, uint8_t peer_idx);
static esp_err_t disco_process_packet(microlink_t *ml, const uint8_t *packet, size_t len,
                                      uint32_t src_ip, uint16_t src_port);

/**
 * @brief Generate random bytes
 */
static void disco_random_bytes(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

/**
 * @brief Build DISCO ping packet
 *
 * @param ml MicroLink context
 * @param peer Target peer
 * @param txid Transaction ID (output, 12 bytes)
 * @param packet Output buffer (min DISCO_MAX_PACKET_SIZE)
 * @return Packet length, or -1 on error
 */
static int disco_build_ping(microlink_t *ml, const microlink_peer_t *peer,
                            uint8_t *txid, uint8_t *packet) {
    // Generate random transaction ID
    disco_random_bytes(txid, DISCO_TXID_LEN);

    // Generate random nonce
    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    // Build plaintext: [type (1)][version (1)][txid (12)][nodekey (32)]
    // Per Tailscale DISCO spec: Ping = type(1) + version(1) + TxID(12) + NodeKey(32) + Padding
    // NodeKey is our WireGuard public key - lets peers validate the ping source
    uint8_t plaintext[1 + 1 + DISCO_TXID_LEN + 32];
    int pt_offset = 0;
    plaintext[pt_offset++] = DISCO_MSG_PING;
    plaintext[pt_offset++] = 0;  // version = 0
    memcpy(plaintext + pt_offset, txid, DISCO_TXID_LEN);
    pt_offset += DISCO_TXID_LEN;
    memcpy(plaintext + pt_offset, ml->wireguard.public_key, 32);

    // Encrypt with NaCl box (our disco key -> peer's disco key)
    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];

    // Use peer's DISCO key for encryption (NOT their WireGuard key)
    if (nacl_box(ciphertext, plaintext, sizeof(plaintext), nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "nacl_box encryption failed");
        return -1;
    }

    // Build packet: [magic][our_disco_pubkey][nonce][ciphertext]
    int offset = 0;
    memcpy(packet + offset, DISCO_MAGIC, DISCO_MAGIC_LEN);
    offset += DISCO_MAGIC_LEN;

    memcpy(packet + offset, ml->wireguard.disco_public_key, DISCO_KEY_LEN);
    offset += DISCO_KEY_LEN;

    memcpy(packet + offset, nonce, DISCO_NONCE_LEN);
    offset += DISCO_NONCE_LEN;

    memcpy(packet + offset, ciphertext, sizeof(ciphertext));
    offset += sizeof(ciphertext);

    return offset;
}

/**
 * @brief Build DISCO pong packet (response to ping)
 *
 * Tailscale DISCO PONG format:
 * Encrypted payload: [type (1)][version (1)][TxID (12)][Src (18)]
 * Src format: IPv6-mapped IPv4 address (16 bytes) + port (2 bytes big-endian)
 *
 * For DERP-relayed pongs, Src is the DERP server address (not meaningful for direct path).
 */
static int disco_build_pong(microlink_t *ml, const microlink_peer_t *peer,
                            const uint8_t *txid, uint32_t src_ip, uint16_t src_port,
                            uint8_t *packet) {
    ESP_LOGD(TAG, "Building PONG: src=%u.%u.%u.%u:%u",
             (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
             (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port);

    // Generate random nonce
    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    // Build plaintext: [type (1)][version (1)][txid (12)][src_addr (18)]
    // src_addr format: IPv6-mapped IPv4 (16 bytes) + port (2 bytes big-endian)
    // IPv6-mapped IPv4 format: ::ffff:A.B.C.D -> 10 zeros, 2x 0xff, then 4-byte IPv4
    uint8_t plaintext[1 + 1 + DISCO_TXID_LEN + 18];
    int pt_offset = 0;

    plaintext[pt_offset++] = DISCO_MSG_PONG;  // type
    plaintext[pt_offset++] = 0;                // version = 0

    memcpy(plaintext + pt_offset, txid, DISCO_TXID_LEN);
    pt_offset += DISCO_TXID_LEN;

    // IPv6-mapped IPv4: 10 bytes of zeros, 2 bytes of 0xff, then 4-byte IPv4
    memset(plaintext + pt_offset, 0, 10);
    pt_offset += 10;
    plaintext[pt_offset++] = 0xff;
    plaintext[pt_offset++] = 0xff;
    // IPv4 address in network byte order (big-endian)
    plaintext[pt_offset++] = (src_ip >> 24) & 0xFF;
    plaintext[pt_offset++] = (src_ip >> 16) & 0xFF;
    plaintext[pt_offset++] = (src_ip >> 8) & 0xFF;
    plaintext[pt_offset++] = src_ip & 0xFF;
    // Port in big-endian
    plaintext[pt_offset++] = (src_port >> 8) & 0xFF;
    plaintext[pt_offset++] = src_port & 0xFF;

    // Encrypt using peer's DISCO key
    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];
    if (nacl_box(ciphertext, plaintext, sizeof(plaintext), nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "nacl_box encryption failed");
        return -1;
    }

    // Build packet
    int offset = 0;
    memcpy(packet + offset, DISCO_MAGIC, DISCO_MAGIC_LEN);
    offset += DISCO_MAGIC_LEN;

    memcpy(packet + offset, ml->wireguard.disco_public_key, DISCO_KEY_LEN);
    offset += DISCO_KEY_LEN;

    memcpy(packet + offset, nonce, DISCO_NONCE_LEN);
    offset += DISCO_NONCE_LEN;

    memcpy(packet + offset, ciphertext, sizeof(ciphertext));
    offset += sizeof(ciphertext);

    return offset;
}

/* IPv6 socket for direct DISCO probes (separate from IPv4) */
static int disco_socket6 = -1;

/**
 * @brief Send UDP packet to IPv4 endpoint
 */
static esp_err_t disco_send_udp4(uint32_t ip, uint16_t port, const uint8_t *data, size_t len) {
    if (disco_socket < 0) {
        ESP_LOGE(TAG, "disco_send_udp4: socket not initialized!");
        return ESP_ERR_INVALID_STATE;
    }

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = ip  // Already network byte order
    };

    int sent = sendto(disco_socket, data, len, 0,
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent < 0) {
        ESP_LOGE(TAG, "sendto IPv4 failed: errno=%d", errno);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * @brief Send UDP packet to IPv6 endpoint
 */
static esp_err_t disco_send_udp6(const uint8_t *ip6, uint16_t port, const uint8_t *data, size_t len) {
    if (disco_socket6 < 0) {
        ESP_LOGW(TAG, "disco_send_udp6: IPv6 socket not initialized, skipping");
        return ESP_ERR_INVALID_STATE;
    }

    struct sockaddr_in6 dest_addr = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
        .sin6_flowinfo = 0,
        .sin6_scope_id = 0
    };
    memcpy(&dest_addr.sin6_addr, ip6, 16);

    int sent = sendto(disco_socket6, data, len, 0,
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent < 0) {
        ESP_LOGE(TAG, "sendto IPv6 failed: errno=%d", errno);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/**
 * @brief Send UDP packet to endpoint (auto-detect IPv4/IPv6)
 */
static esp_err_t disco_send_udp(uint32_t ip, uint16_t port, const uint8_t *data, size_t len) {
    // Legacy IPv4-only function for backwards compatibility
    return disco_send_udp4(ip, port, data, len);
}

/**
 * @brief Send UDP packet to endpoint structure (supports IPv4 and IPv6)
 */
static esp_err_t disco_send_udp_ep(const microlink_endpoint_t *ep, const uint8_t *data, size_t len) {
    if (ep->is_ipv6) {
        return disco_send_udp6(ep->addr.ip6, ep->port, data, len);
    } else {
        return disco_send_udp4(ep->addr.ip4, ep->port, data, len);
    }
}

/**
 * @brief Send DISCO probe to a specific endpoint (supports IPv4 and IPv6)
 */
static esp_err_t disco_probe_endpoint(microlink_t *ml, uint8_t peer_idx, uint8_t ep_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];
    microlink_endpoint_t *ep = &peer->endpoints[ep_idx];
    disco_probe_state_t *probe = &pending_probes[peer_idx][ep_idx];

    // Skip DERP endpoints for direct UDP probes
    if (ep->is_derp) {
        return ESP_OK;
    }

    // Build ping packet
    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return ESP_FAIL;
    }

    // Log endpoint
    if (ep->is_ipv6) {
        ESP_LOGI(TAG, "Sending DISCO PING to [%02x%02x:...:%02x%02x]:%d (IPv6)",
                 ep->addr.ip6[0], ep->addr.ip6[1],
                 ep->addr.ip6[14], ep->addr.ip6[15],
                 ep->port);
    } else {
        uint32_t ip_host = ntohl(ep->addr.ip4);
        ESP_LOGI(TAG, "Sending DISCO PING to %lu.%lu.%lu.%lu:%d",
                 (unsigned long)((ip_host >> 24) & 0xFF),
                 (unsigned long)((ip_host >> 16) & 0xFF),
                 (unsigned long)((ip_host >> 8) & 0xFF),
                 (unsigned long)(ip_host & 0xFF),
                 ep->port);
    }

    esp_err_t err = disco_send_udp_ep(ep, packet, pkt_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "  DISCO PING send FAILED: %d", err);
        return err;
    }

    // Record pending probe
    memcpy(probe->txid, txid, DISCO_TXID_LEN);
    probe->send_time_ms = microlink_get_time_ms();
    probe->pending = true;

    ESP_LOGI(TAG, "  DISCO PING sent OK, awaiting PONG...");
    return ESP_OK;
}

/**
 * @brief Send port spray probes for symmetric NAT hole-punching (from dj-oyu fork)
 *
 * Symmetric NATs assign a new external port for each destination, making
 * traditional hole-punching fail. Port spray sends probes to ±8 ports around
 * the known endpoint, exploiting sequential port allocation patterns.
 *
 * Only called when peer->using_derp is true (direct path failed).
 */
static void disco_port_spray(microlink_t *ml, uint8_t peer_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];

    if (peer->endpoint_count == 0) {
        return;
    }

    int spray_count = 0;
    const int max_sprays = 16;  // Limit total spray probes per round

    // Build one PING packet to reuse for all spray probes
    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return;
    }

    ESP_LOGI(TAG, "Port spray for peer %d (symmetric NAT hole-punch)", peer_idx);

    for (uint8_t ep = 0; ep < peer->endpoint_count && spray_count < max_sprays; ep++) {
        microlink_endpoint_t *endpoint = &peer->endpoints[ep];

        // Skip DERP and IPv6 endpoints
        if (endpoint->is_derp || endpoint->is_ipv6) {
            continue;
        }

        uint16_t base_port = endpoint->port;
        uint32_t ep_ip = endpoint->addr.ip4;

        // Spray ±8 ports around the known endpoint
        for (int offset = -8; offset <= 8 && spray_count < max_sprays; offset++) {
            if (offset == 0) continue;  // Base port already probed normally

            int predicted = (int)base_port + offset;
            if (predicted < 1024 || predicted > 65535) continue;

            // Send probe to predicted port
            struct sockaddr_in dest = {
                .sin_family = AF_INET,
                .sin_port = htons((uint16_t)predicted),
                .sin_addr.s_addr = ep_ip
            };

            int sent = sendto(disco_socket, packet, pkt_len, 0,
                             (struct sockaddr *)&dest, sizeof(dest));
            if (sent > 0) {
                spray_count++;
                ESP_LOGD(TAG, "  Spray probe to port %d", predicted);
            }
        }
    }

    if (spray_count > 0) {
        ESP_LOGI(TAG, "  Sent %d spray probes", spray_count);
    }
}

/**
 * @brief Process incoming DISCO packet
 */
static esp_err_t disco_process_packet(microlink_t *ml, const uint8_t *packet, size_t len,
                                      uint32_t src_ip, uint16_t src_port) {
    // Minimum packet size: magic + key + nonce + encrypted(type + txid) + mac
    size_t min_len = DISCO_MAGIC_LEN + DISCO_KEY_LEN + DISCO_NONCE_LEN + DISCO_MAC_LEN + 1 + DISCO_TXID_LEN;
    if (len < min_len) {
        ESP_LOGD(TAG, "DISCO packet too short: %u", (unsigned int)len);
        return ESP_ERR_INVALID_SIZE;
    }

    // Verify magic
    if (memcmp(packet, DISCO_MAGIC, DISCO_MAGIC_LEN) != 0) {
        return ESP_ERR_INVALID_ARG;  // Not a DISCO packet
    }

    const uint8_t *sender_key = packet + DISCO_MAGIC_LEN;
    const uint8_t *nonce = packet + DISCO_MAGIC_LEN + DISCO_KEY_LEN;
    const uint8_t *ciphertext = nonce + DISCO_NONCE_LEN;
    size_t ciphertext_len = len - DISCO_MAGIC_LEN - DISCO_KEY_LEN - DISCO_NONCE_LEN;

    // Find peer by disco public key
    int peer_idx = -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (memcmp(ml->peers[i].disco_key, sender_key, 32) == 0) {
            peer_idx = i;
            break;
        }
    }

    if (peer_idx < 0) {
        ESP_LOGW(TAG, "DISCO from unknown peer");
        return ESP_ERR_NOT_FOUND;
    }

    microlink_peer_t *peer = &ml->peers[peer_idx];

    // Decrypt payload using nacl_box_open
    // Plaintext: [1-byte type][12-byte txid][optional extra data]
    // Note: Tailscale DISCO can include call-me-maybe with endpoint lists (can be 100+ bytes)
    uint8_t plaintext[256];  // Increased for call-me-maybe endpoint data
    size_t plaintext_len = ciphertext_len - DISCO_MAC_LEN;

    if (plaintext_len > sizeof(plaintext)) {
        ESP_LOGW(TAG, "DISCO payload too large: %u", (unsigned int)plaintext_len);
        return ESP_ERR_NO_MEM;
    }

    // Decrypt: sender_pk is peer's key, recipient_sk is our disco key
    int ret = nacl_box_open(plaintext, ciphertext, ciphertext_len,
                            nonce, sender_key, ml->wireguard.disco_private_key);
    if (ret != 0) {
        ESP_LOGE(TAG, "DISCO decryption failed");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate decrypted payload: [type (1)][version (1)][txid (12)][...]
    if (plaintext_len < 1 + 1 + DISCO_TXID_LEN) {
        ESP_LOGD(TAG, "DISCO payload too short after decrypt: %u", (unsigned int)plaintext_len);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t msg_type = plaintext[0];
    uint8_t msg_version = plaintext[1];
    const uint8_t *txid = plaintext + 2;  // TxID starts after type + version
    (void)msg_version;  // Suppress unused warning

    ESP_LOGD(TAG, "DISCO %s from peer %d",
             msg_type == DISCO_MSG_PING ? "PING" :
             msg_type == DISCO_MSG_PONG ? "PONG" :
             msg_type == DISCO_MSG_CALL_ME_MAYBE ? "CALL_ME_MAYBE" : "UNKNOWN",
             peer_idx);

    switch (msg_type) {
        case DISCO_MSG_PING: {
            // Direct PINGs prove path liveness — update last_seen_ms immediately
            // This prevents race between 30s probe interval and 30s stale threshold (from dj-oyu fork)
            if (src_ip != 0) {
                peer->last_seen_ms = (uint32_t)microlink_get_time_ms();
            }

            // Rate-limit PONG responses when direct path is established.
            // Always respond immediately when searching (using_derp) or first time.
            // This saves CPU cycles from NaCl encryption on every keepalive PING (from dj-oyu fork)
            uint64_t now_pong = microlink_get_time_ms();
            uint64_t last_pong = ml->disco.peer_disco[peer_idx].last_pong_sent_ms;
            bool should_respond = peer->using_derp ||
                                  last_pong == 0 ||
                                  (now_pong - last_pong) >= DISCO_PONG_RATE_LIMIT_MS;

            if (!should_respond) {
                ESP_LOGD(TAG, "PING from peer %d (%s) - PONG rate-limited", peer_idx, peer->hostname);
                break;
            }

            ESP_LOGI(TAG, "PING from peer %d (%s)", peer_idx, peer->hostname);
            uint8_t pong[DISCO_MAX_PACKET_SIZE];
            // For PONG, include the source address where we received the PING from
            // For DERP-relayed pings (src_ip=0), use our VPN IP as the source
            uint32_t pong_src_ip = src_ip;
            uint16_t pong_src_port = src_port;
            if (pong_src_ip == 0) {
                // DERP relay - use our VPN IP (DERP doesn't provide the original source)
                pong_src_ip = ml->vpn_ip;
                pong_src_port = 0;  // No meaningful port for DERP
            }
            int pong_len = disco_build_pong(ml, peer, txid, pong_src_ip, pong_src_port, pong);
            if (pong_len > 0) {
                // =====================================================================
                // OPTIMIZATION: Send direct PONGs FIRST for low-latency LAN responses
                // =====================================================================
                // For LAN peers, direct UDP is sub-10ms while DERP can be 100ms+.
                // By sending direct PONGs first, same-network peers get immediate
                // responses without waiting for DERP socket (which may be congested).
                //
                // Order: Direct UDP -> DERP (fallback)
                // This is the opposite of what we had before, optimizing for the
                // common case where peers are on the same LAN.
                // =====================================================================

                bool direct_sent = false;

                // Helper macro to check if IP is private/LAN (10.x, 192.168.x, 172.16-31.x)
                #define IS_LAN_IP(ip) ( \
                    (((ip) >> 24) == 10) || \
                    (((ip) >> 24) == 192 && (((ip) >> 16) & 0xFF) == 168) || \
                    (((ip) >> 24) == 172 && (((ip) >> 16) & 0xFF) >= 16 && (((ip) >> 16) & 0xFF) <= 31) \
                )

                // FIRST: Send PONG directly to the PING source (fastest path!)
                // This is the most likely to succeed since we know it reached us
                if (src_ip != 0 && src_port != 0) {
                    uint32_t src_ip_net = htonl(src_ip);
                    ESP_LOGI(TAG, "  -> Direct PONG to PING source %lu.%lu.%lu.%lu:%u",
                             (unsigned long)((src_ip >> 24) & 0xFF),
                             (unsigned long)((src_ip >> 16) & 0xFF),
                             (unsigned long)((src_ip >> 8) & 0xFF),
                             (unsigned long)(src_ip & 0xFF),
                             src_port);
                    esp_err_t src_err = disco_send_udp4(src_ip_net, src_port, pong, pong_len);
                    if (src_err == ESP_OK) {
                        direct_sent = true;
                    }
                }

                // SECOND: Try LAN endpoints FIRST (same network = fastest path)
                // For devices on same LAN, this is critical for low latency
                if (peer->endpoint_count > 0) {
                    // Pass 1: Send to ALL LAN IPs (they're most likely to work)
                    for (int ep = 0; ep < peer->endpoint_count; ep++) {
                        microlink_endpoint_t *endpoint = &peer->endpoints[ep];
                        if (endpoint->is_derp || endpoint->is_ipv6) continue;

                        uint32_t ep_ip_host = ntohl(endpoint->addr.ip4);
                        if (IS_LAN_IP(ep_ip_host)) {
                            ESP_LOGI(TAG, "  -> Direct PONG to LAN %lu.%lu.%lu.%lu:%u",
                                     (unsigned long)((ep_ip_host >> 24) & 0xFF),
                                     (unsigned long)((ep_ip_host >> 16) & 0xFF),
                                     (unsigned long)((ep_ip_host >> 8) & 0xFF),
                                     (unsigned long)(ep_ip_host & 0xFF),
                                     endpoint->port);
                            esp_err_t err = disco_send_udp_ep(endpoint, pong, pong_len);
                            if (err == ESP_OK) {
                                direct_sent = true;
                            }
                        }
                    }

                    // Pass 2: If no LAN worked, try ONE public IP (for NAT hole punch)
                    if (!direct_sent) {
                        for (int ep = 0; ep < peer->endpoint_count; ep++) {
                            microlink_endpoint_t *endpoint = &peer->endpoints[ep];
                            if (endpoint->is_derp || endpoint->is_ipv6) continue;

                            uint32_t ep_ip_host = ntohl(endpoint->addr.ip4);
                            if (!IS_LAN_IP(ep_ip_host)) {
                                ESP_LOGI(TAG, "  -> Direct PONG to public %lu.%lu.%lu.%lu:%u",
                                         (unsigned long)((ep_ip_host >> 24) & 0xFF),
                                         (unsigned long)((ep_ip_host >> 16) & 0xFF),
                                         (unsigned long)((ep_ip_host >> 8) & 0xFF),
                                         (unsigned long)(ep_ip_host & 0xFF),
                                         endpoint->port);
                                esp_err_t err = disco_send_udp_ep(endpoint, pong, pong_len);
                                if (err == ESP_OK) {
                                    direct_sent = true;
                                    break;  // One public IP is enough
                                }
                            }
                        }
                    }
                }

                #undef IS_LAN_IP

                // SECOND: Send via DERP as fallback ONLY if direct failed
                // IMPORTANT: Skip DERP if direct already succeeded to avoid blocking!
                // The DERP TLS socket can block for 400ms+ when congested (errno=11),
                // causing "dead periods" where pings time out. Since direct UDP already
                // worked, we don't need the slower DERP path.
                if (!direct_sent) {
                    // No direct path worked - MUST use DERP
                    esp_err_t derp_err = microlink_derp_send(ml, peer->vpn_ip, pong, pong_len);
                    if (derp_err == ESP_OK) {
                        ESP_LOGI(TAG, "PONG sent via DERP (no direct path) to peer %d", peer_idx);
                    } else {
                        ESP_LOGE(TAG, "PONG FAILED - no direct path AND DERP failed!");
                    }
                } else {
                    // Direct succeeded - skip DERP to avoid blocking on congested socket
                    ESP_LOGI(TAG, "PONG direct OK, skipping DERP (avoids 400ms+ congestion block)");
                }
                // Record when we sent this PONG for rate-limiting
                ml->disco.peer_disco[peer_idx].last_pong_sent_ms = now_pong;
            } else {
                ESP_LOGE(TAG, "Failed to build PONG");
            }
            break;
        }

        case DISCO_MSG_PONG: {
            // Find matching probe and calculate RTT
            uint64_t now = microlink_get_time_ms();
            bool found = false;
            bool via_derp = (src_ip == 0);  // src_ip=0 means came via DERP

            // Check all probe slots including the DERP slot (last index)
            // NOTE: Tailscale zeroes the first byte of TxID in PONG responses,
            // so we compare bytes 1-11 only (skip first byte)
            for (int ep = 0; ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                disco_probe_state_t *probe = &pending_probes[peer_idx][ep];
                if (probe->pending && memcmp(probe->txid + 1, txid + 1, DISCO_TXID_LEN - 1) == 0) {
                    uint32_t rtt = (uint32_t)(now - probe->send_time_ms);
                    probe->pending = false;
                    found = true;

                    bool is_derp_slot = (ep == MICROLINK_MAX_ENDPOINTS - 1);

                    // Update peer latency (track best path)
                    if (peer->latency_ms == 0 || rtt < peer->latency_ms) {
                        peer->latency_ms = rtt;
                        peer->best_endpoint_idx = ep;

                        if (is_derp_slot || via_derp) {
                            ESP_LOGI(TAG, "PONG peer %d via DERP: %lums", peer_idx, (unsigned long)rtt);
                            peer->using_derp = true;
                        } else {
                            ESP_LOGI(TAG, "PONG peer %d direct: %lums from %lu.%lu.%lu.%lu:%u",
                                     peer_idx, (unsigned long)rtt,
                                     (unsigned long)((src_ip >> 24) & 0xFF),
                                     (unsigned long)((src_ip >> 16) & 0xFF),
                                     (unsigned long)((src_ip >> 8) & 0xFF),
                                     (unsigned long)(src_ip & 0xFF),
                                     src_port);
                            // Update WireGuard with direct endpoint from PONG source
                            // This enables WireGuard to send data directly instead of via DERP
                            esp_err_t wg_err = microlink_wireguard_update_endpoint(ml, peer->vpn_ip,
                                                                                    src_ip, src_port);
                            if (wg_err == ESP_OK) {
                                ESP_LOGI(TAG, "WireGuard endpoint updated to direct path for peer %d", peer_idx);
                            } else {
                                ESP_LOGW(TAG, "Failed to update WireGuard endpoint: %d", wg_err);
                            }
                            peer->using_derp = false;
                        }
                    }

                    // Initiate WireGuard handshake via DERP ONLY if peer has no direct path.
                    // IMPORTANT: Don't call wireguardif_connect_derp if we have a direct path,
                    // because it clears the endpoint IP and forces DERP relay!
                    if ((is_derp_slot || via_derp) && ml->wireguard.netif) {
                        // Only use DERP handshake if peer is currently using DERP (no direct path)
                        if (peer->using_derp) {
                            extern err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);
                            extern err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);

                            ip_addr_t dummy_ip;
                            u16_t dummy_port;
                            err_t up_err = wireguardif_peer_is_up((struct netif *)ml->wireguard.netif, peer_idx, &dummy_ip, &dummy_port);

                            if (up_err != ERR_OK) {
                                err_t wg_err = wireguardif_connect_derp((struct netif *)ml->wireguard.netif, peer_idx);
                                if (wg_err == ERR_OK) {
                                    ESP_LOGD(TAG, "WG DERP handshake initiated for peer %d", peer_idx);
                                } else {
                                    ESP_LOGW(TAG, "WG DERP handshake failed: %d", wg_err);
                                }
                            }
                        } else {
                            ESP_LOGI(TAG, "Skipping DERP handshake for peer %d - direct path established", peer_idx);
                        }
                    }

                    peer->last_seen_ms = now;
                    break;
                }
            }

            if (!found) {
                ESP_LOGD(TAG, "PONG from peer %d - no matching probe", peer_idx);

                if (!via_derp) {
                    // Accept unmatched direct PONGs when peer is using DERP (spray probe responses)
                    // Port spray sends probes with same TxID to multiple ports, so we may not
                    // have an exact probe->txid match. Trust direct PONGs from known peers. (from dj-oyu fork)
                    if (peer->using_derp) {
                        ESP_LOGI(TAG, "Spray PONG success! Peer %d from %lu.%lu.%lu.%lu:%u",
                                 peer_idx,
                                 (unsigned long)((src_ip >> 24) & 0xFF),
                                 (unsigned long)((src_ip >> 16) & 0xFF),
                                 (unsigned long)((src_ip >> 8) & 0xFF),
                                 (unsigned long)(src_ip & 0xFF),
                                 src_port);
                        microlink_wireguard_update_endpoint(ml, peer->vpn_ip, src_ip, src_port);

                        peer->last_seen_ms = now;
                        peer->using_derp = false;
                    } else {
                        // Pong from unexpected source - might be hole-punching success
                        for (int ep = 0; ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                            disco_probe_state_t *probe = &pending_probes[peer_idx][ep];
                            if (probe->pending && memcmp(probe->txid, txid, DISCO_TXID_LEN) == 0) {
                                uint32_t rtt = (uint32_t)(now - probe->send_time_ms);
                                probe->pending = false;

                                ESP_LOGI(TAG, "Hole-punch success! Peer %d RTT=%lums", peer_idx, (unsigned long)rtt);
                                microlink_wireguard_update_endpoint(ml, peer->vpn_ip, src_ip, src_port);

                                peer->latency_ms = rtt;
                                peer->last_seen_ms = now;
                                peer->using_derp = false;
                                break;
                            }
                        }
                    }
                } else {
                    // PONG via DERP but no matching probe - still try to connect
                    peer->using_derp = true;
                    peer->last_seen_ms = now;

                    if (ml->wireguard.netif) {
                        extern err_t wireguardif_peer_is_up(struct netif *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port);
                        extern err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);

                        ip_addr_t dummy_ip;
                        u16_t dummy_port;
                        err_t up_err = wireguardif_peer_is_up((struct netif *)ml->wireguard.netif, peer_idx, &dummy_ip, &dummy_port);

                        if (up_err != ERR_OK) {
                            wireguardif_connect_derp((struct netif *)ml->wireguard.netif, peer_idx);
                        }
                    }
                }
            }
            break;
        }

        case DISCO_MSG_CALL_ME_MAYBE: {
            // =====================================================================
            // SIMULTANEOUS HOLE PUNCHING (Critical for NAT traversal)
            // =====================================================================
            // When we receive CallMeMaybe, the peer is saying "I want to connect,
            // here are my endpoints, please probe them NOW."
            //
            // For NAT hole punching to work, BOTH sides must send packets at the
            // same time. The sequence is:
            //   1. Peer sends CallMeMaybe with their endpoints
            //   2. We IMMEDIATELY send DISCO pings to ALL their endpoints
            //   3. We ALSO send CallMeMaybe back so peer probes our endpoints
            //   4. Both sides' pings "punch holes" in their respective NATs
            //   5. Responses flow through the holes
            //
            // This is the KEY difference vs PC Tailscale - PC does this correctly,
            // we were only doing step 2 without step 3.
            // =====================================================================

            ESP_LOGI(TAG, "CallMeMaybe from peer %d, payload_len=%u", peer_idx, (unsigned int)plaintext_len);

            // Parse endpoints from CallMeMaybe (skip type and version bytes)
            // IMPORTANT: Do NOT overwrite peer->endpoints! Those are from coordination
            // server and are authoritative. CMM endpoints are temporary probing targets.
            // (Fix from dj-oyu fork)
            size_t endpoint_data_start = 2;  // After type + version
            size_t endpoint_size = 18;       // IPv6-mapped-IPv4 (16) + port (2)
            int cmm_endpoint_count = 0;

            // Temporary storage for CMM endpoints (don't overwrite peer->endpoints)
            struct {
                uint32_t ip4;
                uint16_t port;
                bool is_ipv6;
                uint8_t ip6[16];
            } cmm_endpoints[MICROLINK_MAX_ENDPOINTS];

            for (size_t offset = endpoint_data_start;
                 offset + endpoint_size <= plaintext_len && cmm_endpoint_count < MICROLINK_MAX_ENDPOINTS;
                 offset += endpoint_size) {

                const uint8_t *ep_data = plaintext + offset;

                // Check for IPv6-mapped-IPv4 format: first 10 bytes = 0, then 2 bytes = 0xff
                bool is_ipv4_mapped = true;
                for (int i = 0; i < 10; i++) {
                    if (ep_data[i] != 0) {
                        is_ipv4_mapped = false;
                        break;
                    }
                }
                if (ep_data[10] != 0xff || ep_data[11] != 0xff) {
                    is_ipv4_mapped = false;
                }

                // Extract port (bytes 16-17) - big endian
                uint16_t port = ((uint16_t)ep_data[16] << 8) | ep_data[17];

                if (port == 0) {
                    continue;  // Skip invalid endpoints
                }

                if (is_ipv4_mapped) {
                    // Extract IPv4 (bytes 12-15) - packet is in network byte order (big-endian)
                    uint32_t ipv4_host = ((uint32_t)ep_data[12] << 24) |
                                         ((uint32_t)ep_data[13] << 16) |
                                         ((uint32_t)ep_data[14] << 8) |
                                         (uint32_t)ep_data[15];
                    uint32_t ipv4 = htonl(ipv4_host);  // Convert to network byte order

                    if (ipv4 != 0) {
                        cmm_endpoints[cmm_endpoint_count].ip4 = ipv4;
                        cmm_endpoints[cmm_endpoint_count].port = port;
                        cmm_endpoints[cmm_endpoint_count].is_ipv6 = false;
                        cmm_endpoint_count++;

                        ESP_LOGI(TAG, "  CallMeMaybe IPv4[%d]: %lu.%lu.%lu.%lu:%u",
                                 cmm_endpoint_count - 1,
                                 (unsigned long)((ipv4_host >> 24) & 0xFF),
                                 (unsigned long)((ipv4_host >> 16) & 0xFF),
                                 (unsigned long)((ipv4_host >> 8) & 0xFF),
                                 (unsigned long)(ipv4_host & 0xFF),
                                 port);
                    }
                } else {
                    // Native IPv6 address - copy all 16 bytes
                    memcpy(cmm_endpoints[cmm_endpoint_count].ip6, ep_data, 16);
                    cmm_endpoints[cmm_endpoint_count].port = port;
                    cmm_endpoints[cmm_endpoint_count].is_ipv6 = true;
                    cmm_endpoint_count++;

                    // Log IPv6 (first and last 2 bytes for brevity)
                    ESP_LOGI(TAG, "  CallMeMaybe IPv6[%d]: %02x%02x:...:%02x%02x:%u",
                             cmm_endpoint_count - 1,
                             ep_data[0], ep_data[1], ep_data[14], ep_data[15],
                             port);
                }
            }

            ESP_LOGI(TAG, "CallMeMaybe: parsed %d endpoints from peer %d (%s) [preserving %d coord endpoints]",
                     cmm_endpoint_count, peer_idx, peer->hostname, peer->endpoint_count);

            // Trigger probing of this peer
            ml->disco.peer_disco[peer_idx].active = true;

            // =====================================================================
            // STEP 1: IMMEDIATELY probe ALL CMM endpoints (time-critical!)
            // =====================================================================
            // Send probes directly WITHOUT storing in peer->endpoints.
            // PONGs from these probes will be handled by the "spray hole-punch"
            // fallback in the PONG handler (unmatched direct PONG from known peer).
            if (cmm_endpoint_count > 0) {
                ESP_LOGI(TAG, "SIMULTANEOUS HOLE PUNCH: Probing %d CMM endpoints IMMEDIATELY!", cmm_endpoint_count);
                for (int ep = 0; ep < cmm_endpoint_count; ep++) {
                    if (cmm_endpoints[ep].is_ipv6) {
                        // IPv6 - send via IPv6 socket
                        uint8_t packet[DISCO_MAX_PACKET_SIZE];
                        uint8_t txid[DISCO_TXID_LEN];
                        int pkt_len = disco_build_ping(ml, peer, txid, packet);
                        if (pkt_len > 0) {
                            disco_send_udp6(cmm_endpoints[ep].ip6, cmm_endpoints[ep].port, packet, pkt_len);
                        }
                    } else {
                        // IPv4 - send directly
                        uint8_t packet[DISCO_MAX_PACKET_SIZE];
                        uint8_t txid[DISCO_TXID_LEN];
                        int pkt_len = disco_build_ping(ml, peer, txid, packet);
                        if (pkt_len > 0) {
                            disco_send_udp4(cmm_endpoints[ep].ip4, cmm_endpoints[ep].port, packet, pkt_len);
                        }
                    }
                }
            }

            // Also probe existing peer endpoints from coordination server
            for (int ep = 0; ep < peer->endpoint_count && ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                disco_probe_endpoint(ml, peer_idx, ep);
            }

            // Also probe via DERP as fallback
            disco_probe_via_derp(ml, peer_idx);

            // =====================================================================
            // STEP 2: Send CallMeMaybe BACK so peer probes OUR endpoints
            // =====================================================================
            // This is the CRITICAL missing piece! Without this, peer's pings hit
            // our NAT but we never sent anything to punch a hole from our side.
            //
            // Note: We limit how often we send CallMeMaybe back to avoid ping-pong
            static uint64_t last_cmm_response[MICROLINK_MAX_PEERS] = {0};
            uint64_t now = microlink_get_time_ms();

            if (now - last_cmm_response[peer_idx] >= 2000) {  // Max once per 2 seconds
                last_cmm_response[peer_idx] = now;

                ESP_LOGI(TAG, "SIMULTANEOUS HOLE PUNCH: Sending CallMeMaybe BACK to peer %d", peer_idx);
                esp_err_t cmm_ret = microlink_disco_send_call_me_maybe(ml, peer->vpn_ip);
                if (cmm_ret == ESP_OK) {
                    ESP_LOGI(TAG, "  CallMeMaybe response sent - peer will now probe our endpoints");
                } else {
                    ESP_LOGW(TAG, "  Failed to send CallMeMaybe response: %d", cmm_ret);
                }
            } else {
                ESP_LOGD(TAG, "Skipping CallMeMaybe response (rate limited, last=%llums ago)",
                         (unsigned long long)(now - last_cmm_response[peer_idx]));
            }
            break;
        }

        default:
            ESP_LOGD(TAG, "Unknown DISCO message type: 0x%02x", msg_type);
            break;
    }

    return ESP_OK;
}

/**
 * @brief High-priority DISCO receive task
 *
 * This task runs at 200Hz (every 5ms) to ensure immediate PONG responses.
 * Without this, PONG latency depends on how often the main loop calls
 * microlink_update(), which may be 10-50ms or more.
 *
 * This is the key to achieving PC-like ping consistency.
 */
static void disco_receive_task(void *arg) {
    microlink_t *ml = (microlink_t *)arg;
    uint8_t rx_buf[DISCO_MAX_PACKET_SIZE];
    struct sockaddr_in src_addr;
    socklen_t addr_len;

    ESP_LOGI(TAG, "DISCO receive task started (200Hz polling for fast PONGs)");

    while (disco_task_running) {
        if (disco_socket < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // Process up to a few packets per cycle, then yield
        // This prevents watchdog issues from tight looping
        int packets_this_cycle = 0;
        const int max_packets_per_cycle = 4;

        while (packets_this_cycle < max_packets_per_cycle) {
            addr_len = sizeof(src_addr);
            int len = recvfrom(disco_socket, rx_buf, sizeof(rx_buf), 0,
                              (struct sockaddr *)&src_addr, &addr_len);

            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;  // No more packets
                }
                break;  // Other error
            }

            if (len > 0) {
                packets_this_cycle++;
                uint32_t src_ip = ntohl(src_addr.sin_addr.s_addr);
                uint16_t src_port = ntohs(src_addr.sin_port);

                ESP_LOGI(TAG, "[FAST] DISCO UDP received: %d bytes from %lu.%lu.%lu.%lu:%u",
                         len,
                         (unsigned long)((src_ip >> 24) & 0xFF),
                         (unsigned long)((src_ip >> 16) & 0xFF),
                         (unsigned long)((src_ip >> 8) & 0xFF),
                         (unsigned long)(src_ip & 0xFF),
                         src_port);

                // Check if this is a WireGuard packet (type 1-4 in first byte)
                // WireGuard packets arriving on DISCO port need to be routed to WG handler
                if (len >= 4) {
                    uint8_t wg_type = rx_buf[0];
                    // WireGuard message types: 1=init, 2=resp, 3=cookie, 4=data
                    // Also check reserved bytes are 0 for handshake types
                    if (wg_type >= 1 && wg_type <= 4 &&
                        (wg_type == 4 || (rx_buf[1] == 0 && rx_buf[2] == 0 && rx_buf[3] == 0))) {
                        ESP_LOGI(TAG, "[FAST] WireGuard packet detected on DISCO port! type=%d len=%d from %lu.%lu.%lu.%lu:%u",
                                 wg_type, len,
                                 (unsigned long)((src_ip >> 24) & 0xFF),
                                 (unsigned long)((src_ip >> 16) & 0xFF),
                                 (unsigned long)((src_ip >> 8) & 0xFF),
                                 (unsigned long)(src_ip & 0xFF),
                                 src_port);
                        // Inject into WireGuard handler with actual source IP and port
                        // src_ip is host byte order, convert to network byte order for injection
                        uint32_t src_ip_net = htonl(src_ip);
                        esp_err_t inject_err = microlink_wireguard_inject_packet(ml, src_ip_net, src_port,
                                                                                  rx_buf, len);
                        if (inject_err == ESP_OK) {
                            ESP_LOGI(TAG, "[MAGICSOCK] WireGuard packet injected from %lu.%lu.%lu.%lu:%u",
                                     (unsigned long)((src_ip >> 24) & 0xFF),
                                     (unsigned long)((src_ip >> 16) & 0xFF),
                                     (unsigned long)((src_ip >> 8) & 0xFF),
                                     (unsigned long)(src_ip & 0xFF),
                                     src_port);
                        } else {
                            ESP_LOGW(TAG, "[MAGICSOCK] Failed to inject WireGuard packet: %d", inject_err);
                        }
                        continue;  // Skip DISCO processing for WG packets
                    }
                }

                // Process immediately for fast PONG response
                disco_process_packet(ml, rx_buf, len, src_ip, src_port);
            }
        }

        // ALWAYS yield to prevent watchdog - this is critical!
        // 10ms delay = 100Hz polling, still fast enough for responsive PONGs
        vTaskDelay(pdMS_TO_TICKS(DISCO_POLL_INTERVAL_MS));
    }

    ESP_LOGI(TAG, "DISCO receive task stopped");
    disco_task_handle = NULL;
    vTaskDelete(NULL);
}

/**
 * @brief Start the DISCO receive task
 */
static esp_err_t disco_start_receive_task(microlink_t *ml) {
    if (disco_task_handle != NULL) {
        return ESP_OK;  // Already running
    }

    disco_task_ml = ml;
    disco_task_running = true;

    BaseType_t ret = xTaskCreatePinnedToCore(
        disco_receive_task,
        "disco_rx",
        DISCO_TASK_STACK_SIZE,
        ml,
        DISCO_TASK_PRIORITY,
        &disco_task_handle,
        0  // Core 0 (same as DERP/state machine)
    );

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create DISCO receive task");
        disco_task_running = false;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "DISCO receive task created (high-priority fast PONG)");
    return ESP_OK;
}

/**
 * @brief Stop the DISCO receive task
 */
static void disco_stop_receive_task(void) {
    if (disco_task_handle == NULL) {
        return;
    }

    disco_task_running = false;

    // Wait for task to stop (max 500ms)
    for (int i = 0; i < 50 && disco_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    if (disco_task_handle != NULL) {
        ESP_LOGW(TAG, "DISCO receive task did not stop gracefully, deleting");
        vTaskDelete(disco_task_handle);
        disco_task_handle = NULL;
    }

    disco_task_ml = NULL;
}

esp_err_t microlink_disco_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing DISCO protocol (IPv4 + IPv6 + fast PONG task)");

    memset(&ml->disco, 0, sizeof(microlink_disco_t));
    memset(pending_probes, 0, sizeof(pending_probes));

    // Create IPv4 UDP socket for direct DISCO probes
    disco_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (disco_socket < 0) {
        ESP_LOGE(TAG, "Failed to create IPv4 DISCO socket: errno=%d", errno);
        return ESP_FAIL;
    }

    // Bind IPv4 to WireGuard port 51820 (magicsock mode - single socket for DISCO + WG)
    // This ensures the port we advertise to coordination server matches what we listen on
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(51821),  // WireGuard standard port
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(disco_socket, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind IPv4 DISCO socket: errno=%d", errno);
        close(disco_socket);
        disco_socket = -1;
        return ESP_FAIL;
    }

    // Set IPv4 non-blocking
    int flags = fcntl(disco_socket, F_GETFL, 0);
    fcntl(disco_socket, F_SETFL, flags | O_NONBLOCK);

    // Verify we got port 51820
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    getsockname(disco_socket, (struct sockaddr *)&local_addr, &addr_len);
    ml->disco.local_port = ntohs(local_addr.sin_port);
    ESP_LOGI(TAG, "DISCO/magicsock bound to port %d (WireGuard port)", ml->disco.local_port);
    if (ml->disco.local_port != 51821) {
        ESP_LOGW(TAG, "Warning: Expected port 51821, got %d", ml->disco.local_port);
    }

    // Create IPv6 UDP socket (optional - may fail if IPv6 not available)
    disco_socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (disco_socket6 >= 0) {
        // Bind IPv6 to same port as IPv4 for simplicity
        struct sockaddr_in6 bind_addr6 = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(ml->disco.local_port),
            .sin6_addr = IN6ADDR_ANY_INIT
        };
        if (bind(disco_socket6, (struct sockaddr *)&bind_addr6, sizeof(bind_addr6)) < 0) {
            ESP_LOGW(TAG, "Failed to bind IPv6 DISCO socket: errno=%d (IPv6 disabled)", errno);
            close(disco_socket6);
            disco_socket6 = -1;
        } else {
            // Set IPv6 non-blocking
            flags = fcntl(disco_socket6, F_GETFL, 0);
            fcntl(disco_socket6, F_SETFL, flags | O_NONBLOCK);
            ESP_LOGI(TAG, "DISCO IPv6 socket bound to port %d", ml->disco.local_port);
        }
    } else {
        ESP_LOGW(TAG, "IPv6 socket creation failed: errno=%d (IPv6 disabled)", errno);
    }

    ESP_LOGI(TAG, "DISCO initialized (IPv4=%s, IPv6=%s)",
             disco_socket >= 0 ? "OK" : "FAIL",
             disco_socket6 >= 0 ? "OK" : "FAIL");

    // Start high-priority receive task for fast PONG responses
    // This is the KEY to achieving PC-like ping consistency!
    esp_err_t task_err = disco_start_receive_task(ml);
    if (task_err != ESP_OK) {
        ESP_LOGW(TAG, "DISCO receive task failed to start (PONGs will be slower)");
        // Non-fatal - main loop can still process DISCO packets
    }

    return ESP_OK;
}

esp_err_t microlink_disco_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing DISCO protocol");

    // Stop receive task first
    disco_stop_receive_task();

    if (disco_socket >= 0) {
        close(disco_socket);
        disco_socket = -1;
    }

    if (disco_socket6 >= 0) {
        close(disco_socket6);
        disco_socket6 = -1;
    }

    memset(&ml->disco, 0, sizeof(microlink_disco_t));
    memset(pending_probes, 0, sizeof(pending_probes));

    ESP_LOGI(TAG, "DISCO deinitialized");
    return ESP_OK;
}

int microlink_disco_get_socket(void) {
    return disco_socket;
}

esp_err_t microlink_disco_probe_peers(microlink_t *ml) {
    uint64_t now = microlink_get_time_ms();

    // =========================================================================
    // LAZY PROBING STRATEGY (like Tailscale)
    // =========================================================================
    // Don't constantly probe all endpoints - this causes DERP congestion!
    //
    // Instead:
    // 1. Initial: Send ONE CallMeMaybe to each peer via DERP
    // 2. Reactive: When we receive a PING, respond with PONG (establishes path)
    // 3. Stale: Only re-probe if path is stale (>30s since last seen) AND
    //           the peer doesn't have an established direct path
    // 4. On-demand: Probe when we need to send data but path is unknown
    //
    // This dramatically reduces DERP traffic and prevents socket congestion.
    // =========================================================================

    // Global check just to avoid calling too frequently
    if (now - ml->disco.last_global_disco_ms < 1000) {  // At most 1/second
        return ESP_OK;
    }
    ml->disco.last_global_disco_ms = now;

    ESP_LOGD(TAG, "DISCO maintenance check for %d peers", ml->peer_count);

    for (uint8_t i = 0; i < ml->peer_count; i++) {
        microlink_peer_t *peer = &ml->peers[i];

        // Use adaptive probe intervals based on path state (from dj-oyu fork):
        // - 5s when searching for direct path (using_derp=true or never seen)
        // - 30s when direct path is established
        uint64_t probe_interval = (peer->using_derp || peer->last_seen_ms == 0)
                                  ? DISCO_PROBE_INTERVAL_SEARCH_MS
                                  : DISCO_PROBE_INTERVAL_DIRECT_MS;

        // Skip if we recently probed this peer
        if (now - ml->disco.peer_disco[i].last_probe_ms < probe_interval) {
            continue;
        }

        // Skip peers that have an active direct path (last_seen within stale threshold)
        bool path_active = (peer->last_seen_ms > 0) &&
                          (now - peer->last_seen_ms < DISCO_STALE_THRESHOLD_MS);

        if (path_active && !peer->using_derp) {
            ESP_LOGD(TAG, "Peer %d has active direct path, maintenance probe", i);
            // Still probe but at slower 30s interval (already handled above)
        }

        // For stale/unknown paths, send ONE direct probe to first endpoint (if any)
        // Don't spam all endpoints - let the PONG response establish the path
        if (peer->endpoint_count > 0 && !peer->endpoints[0].is_derp) {
            ESP_LOGI(TAG, "Peer %d path stale/unknown, sending single probe", i);
            disco_probe_endpoint(ml, i, 0);  // Just probe first endpoint

            // If peer is using DERP (direct path failed), try port spray for symmetric NAT
            // This exploits sequential port allocation to find the peer's actual port (from dj-oyu fork)
            if (peer->using_derp) {
                disco_port_spray(ml, i);
            }
        } else if (!path_active) {
            // No direct endpoints and path is stale - try DERP
            ESP_LOGI(TAG, "Peer %d has no direct endpoints, probing via DERP", i);
            disco_probe_via_derp(ml, i);
        }

        ml->disco.peer_disco[i].last_probe_ms = now;
    }

    return ESP_OK;
}

esp_err_t microlink_disco_update_paths(microlink_t *ml) {
    if (disco_socket < 0) {
        return ESP_ERR_INVALID_STATE;
    }

    uint64_t now = microlink_get_time_ms();

    // =========================================================================
    // NOTE: High-priority receive is now handled by disco_receive_task()
    // which polls at 200Hz for fast PONG responses. The code below is kept
    // as a FALLBACK in case the task isn't running (e.g., task creation failed).
    // =========================================================================
    if (!disco_task_running) {
        // Fallback: receive DISCO packets in main loop (slower)
        uint8_t rx_buf[DISCO_MAX_PACKET_SIZE];
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);

        while (1) {
            int len = recvfrom(disco_socket, rx_buf, sizeof(rx_buf), 0,
                              (struct sockaddr *)&src_addr, &addr_len);
            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;  // No more packets
                }
                ESP_LOGD(TAG, "recvfrom error: errno=%d", errno);
                break;
            }

            uint32_t src_ip = ntohl(src_addr.sin_addr.s_addr);
            uint16_t src_port = ntohs(src_addr.sin_port);

            ESP_LOGI(TAG, "[SLOW] DISCO UDP received: %d bytes from %lu.%lu.%lu.%lu:%u",
                     len,
                     (unsigned long)((src_ip >> 24) & 0xFF),
                     (unsigned long)((src_ip >> 16) & 0xFF),
                     (unsigned long)((src_ip >> 8) & 0xFF),
                     (unsigned long)(src_ip & 0xFF),
                     src_port);

            disco_process_packet(ml, rx_buf, len, src_ip, src_port);
        }
    }

    // Check for probe timeouts and update path state
    for (uint8_t i = 0; i < ml->peer_count; i++) {
        microlink_peer_t *peer = &ml->peers[i];

        for (uint8_t ep = 0; ep < peer->endpoint_count; ep++) {
            disco_probe_state_t *probe = &pending_probes[i][ep];

            // Check for timeout
            if (probe->pending && (now - probe->send_time_ms) > DISCO_PROBE_TIMEOUT_MS) {
                probe->pending = false;
                ESP_LOGD(TAG, "DISCO probe timeout: peer %d endpoint %d", i, ep);
            }
        }

        // Mark peer as stale if not seen recently and reset to DERP fallback
        // This ensures WG doesn't keep trying a dead direct path (from dj-oyu fork)
        if (peer->last_seen_ms > 0 && (now - peer->last_seen_ms) > DISCO_STALE_THRESHOLD_MS) {
            ESP_LOGW(TAG, "Peer %d path stale (no response in %lums), reverting to DERP",
                     i, (unsigned long)(now - peer->last_seen_ms));

            // Reset WG peer endpoint to 0.0.0.0:0 so packets go via DERP callback
            if (!peer->using_derp && ml->wireguard.netif) {
                extern err_t wireguardif_connect_derp(struct netif *netif, u8_t peer_index);
                err_t err = wireguardif_connect_derp((struct netif *)ml->wireguard.netif, i);
                if (err == ERR_OK) {
                    ESP_LOGI(TAG, "Peer %d WG endpoint reset to DERP", i);
                }
            }
            peer->using_derp = true;
        }
    }

    return ESP_OK;
}

/**
 * @brief Send DISCO probe to peer via DERP relay
 *
 * This is essential for NAT traversal - peers behind NAT can't receive
 * direct UDP probes, so we must also probe via DERP.
 */
static esp_err_t disco_probe_via_derp(microlink_t *ml, uint8_t peer_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];

    if (!ml->derp.connected) {
        ESP_LOGD(TAG, "DERP not connected, skipping DERP probe");
        return ESP_ERR_INVALID_STATE;
    }

    // Build ping packet
    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return ESP_FAIL;
    }

    // Send via DERP relay
    esp_err_t err = microlink_derp_send(ml, peer->vpn_ip, packet, pkt_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Failed to send DISCO via DERP: %d", err);
        return err;
    }

    // Use a special slot for DERP probes (last endpoint slot)
    disco_probe_state_t *probe = &pending_probes[peer_idx][MICROLINK_MAX_ENDPOINTS - 1];
    memcpy(probe->txid, txid, DISCO_TXID_LEN);
    probe->send_time_ms = microlink_get_time_ms();
    probe->pending = true;

    ESP_LOGD(TAG, "DISCO ping via DERP to peer %d", peer_idx);
    return ESP_OK;
}

esp_err_t microlink_disco_handle_derp_packet(microlink_t *ml, const uint8_t *src_key,
                                              const uint8_t *data, size_t len) {
    // Check for DISCO magic
    if (len < DISCO_MAGIC_LEN || memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) != 0) {
        return ESP_ERR_INVALID_ARG;  // Not a DISCO packet
    }

    // Find peer by WireGuard public key (src_key from DERP frame is WG pubkey)
    int peer_idx = -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (memcmp(ml->peers[i].public_key, src_key, 32) == 0) {
            peer_idx = i;
            break;
        }
    }

    if (peer_idx < 0) {
        ESP_LOGW(TAG, "DISCO from unknown DERP peer");
        return ESP_ERR_NOT_FOUND;
    }

    // Update disco key if it differs from packet header (handles key rotation)
    if (len >= DISCO_MAGIC_LEN + DISCO_KEY_LEN) {
        const uint8_t *disco_sender_key = data + DISCO_MAGIC_LEN;
        microlink_peer_t *peer = &ml->peers[peer_idx];

        if (memcmp(peer->disco_key, disco_sender_key, 32) != 0) {
            ESP_LOGI(TAG, "Peer %d disco_key updated", peer_idx);
            memcpy(peer->disco_key, disco_sender_key, 32);
        }
    }

    // Process the DISCO packet - use 0 for IP/port since it came via DERP
    return disco_process_packet(ml, data, len, 0, 0);
}

bool microlink_disco_is_disco_packet(const uint8_t *data, size_t len) {
    return (len >= DISCO_MAGIC_LEN && memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) == 0);
}

/**
 * @brief Send DISCO CallMeMaybe to a specific peer
 *
 * CallMeMaybe tells the peer "please try to connect to me" and includes
 * our endpoints. This is used to trigger peer-initiated WireGuard handshakes
 * when ESP32-initiated handshakes don't complete due to NAT/firewall asymmetry.
 *
 * CallMeMaybe format (encrypted payload):
 * - 1 byte: message type (0x03)
 * - 1 byte: version (0x00)
 * - N * 18 bytes: endpoint list (IPv6-mapped-IPv4 + port)
 *
 * The peer will receive this and attempt to connect to each endpoint listed.
 */
esp_err_t microlink_disco_send_call_me_maybe(microlink_t *ml, uint32_t peer_vpn_ip) {
    if (!ml || !ml->derp.connected) {
        return ESP_ERR_INVALID_STATE;
    }

    // Find peer by VPN IP
    int peer_idx = -1;
    for (int i = 0; i < ml->peer_count; i++) {
        if (ml->peers[i].vpn_ip == peer_vpn_ip) {
            peer_idx = i;
            break;
        }
    }

    if (peer_idx < 0) {
        ESP_LOGW(TAG, "CallMeMaybe: peer not found for VPN IP");
        return ESP_ERR_NOT_FOUND;
    }

    microlink_peer_t *peer = &ml->peers[peer_idx];

    // Generate random nonce
    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    // Build plaintext: [type (1)][version (1)][endpoints (N * 18)]
    // Each endpoint is: IPv6-mapped-IPv4 (16 bytes) + port (2 bytes big-endian)
    // Include BOTH local LAN IP and STUN public IP for maximum connectivity
    uint8_t plaintext[2 + 3 * 18];  // type + version + up to 3 endpoints
    int pt_offset = 0;
    int endpoint_count = 0;

    plaintext[pt_offset++] = DISCO_MSG_CALL_ME_MAYBE;  // type
    plaintext[pt_offset++] = 0;                         // version = 0

    // Get local LAN IP from WiFi interface (critical for same-network peers!)
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            // Convert from network byte order to host byte order for logging
            uint32_t local_ip = ntohl(ip_info.ip.addr);
            // Use DISCO socket port - this is where we receive DISCO pings!
            uint16_t local_port = ml->disco.local_port;

            // Add local LAN endpoint (IPv6-mapped-IPv4 format)
            memset(plaintext + pt_offset, 0, 10);
            pt_offset += 10;
            plaintext[pt_offset++] = 0xff;
            plaintext[pt_offset++] = 0xff;
            // IPv4 in big-endian (network byte order in packet)
            plaintext[pt_offset++] = (local_ip >> 24) & 0xFF;
            plaintext[pt_offset++] = (local_ip >> 16) & 0xFF;
            plaintext[pt_offset++] = (local_ip >> 8) & 0xFF;
            plaintext[pt_offset++] = local_ip & 0xFF;
            // Port in big-endian
            plaintext[pt_offset++] = (local_port >> 8) & 0xFF;
            plaintext[pt_offset++] = local_port & 0xFF;
            endpoint_count++;

            ESP_LOGI(TAG, "CallMeMaybe includes LOCAL endpoint: %lu.%lu.%lu.%lu:%u",
                     (unsigned long)((local_ip >> 24) & 0xFF),
                     (unsigned long)((local_ip >> 16) & 0xFF),
                     (unsigned long)((local_ip >> 8) & 0xFF),
                     (unsigned long)(local_ip & 0xFF),
                     local_port);
        }
    }

    // Add STUN (public) endpoint if we have one
    if (ml->stun.public_ip != 0) {
        // IPv6-mapped-IPv4: 10 bytes zeros, 2 bytes 0xff, 4 bytes IPv4
        memset(plaintext + pt_offset, 0, 10);
        pt_offset += 10;
        plaintext[pt_offset++] = 0xff;
        plaintext[pt_offset++] = 0xff;
        // IPv4 in network byte order
        plaintext[pt_offset++] = (ml->stun.public_ip >> 24) & 0xFF;
        plaintext[pt_offset++] = (ml->stun.public_ip >> 16) & 0xFF;
        plaintext[pt_offset++] = (ml->stun.public_ip >> 8) & 0xFF;
        plaintext[pt_offset++] = ml->stun.public_ip & 0xFF;
        // Port - use STUN-discovered port if available (NAT assigns external port)
        uint16_t my_port = (ml->stun.public_port != 0) ? ml->stun.public_port : ml->wireguard.listen_port;
        plaintext[pt_offset++] = (my_port >> 8) & 0xFF;
        plaintext[pt_offset++] = my_port & 0xFF;
        endpoint_count++;

        char ip_buf[16];
        ESP_LOGI(TAG, "CallMeMaybe includes STUN endpoint: %s:%u",
                 microlink_vpn_ip_to_str(ml->stun.public_ip, ip_buf), my_port);
    }

    if (endpoint_count == 0) {
        ESP_LOGW(TAG, "CallMeMaybe: no endpoints available!");
    }

    // Encrypt using peer's DISCO key
    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];
    if (nacl_box(ciphertext, plaintext, pt_offset, nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "CallMeMaybe encryption failed");
        return ESP_FAIL;
    }

    // Build full packet: [magic][our_disco_pubkey][nonce][ciphertext]
    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    int pkt_offset = 0;

    memcpy(packet + pkt_offset, DISCO_MAGIC, DISCO_MAGIC_LEN);
    pkt_offset += DISCO_MAGIC_LEN;

    memcpy(packet + pkt_offset, ml->wireguard.disco_public_key, DISCO_KEY_LEN);
    pkt_offset += DISCO_KEY_LEN;

    memcpy(packet + pkt_offset, nonce, DISCO_NONCE_LEN);
    pkt_offset += DISCO_NONCE_LEN;

    size_t ciphertext_len = pt_offset + DISCO_MAC_LEN;
    memcpy(packet + pkt_offset, ciphertext, ciphertext_len);
    pkt_offset += ciphertext_len;

    // Send via DERP relay
    esp_err_t err = microlink_derp_send(ml, peer_vpn_ip, packet, pkt_offset);
    if (err == ESP_OK) {
        char ip_buf[16];
        ESP_LOGI(TAG, "CallMeMaybe sent to peer %d (%s) via DERP",
                 peer_idx, microlink_vpn_ip_to_str(peer_vpn_ip, ip_buf));
    } else {
        ESP_LOGE(TAG, "Failed to send CallMeMaybe via DERP: %d", err);
    }

    return err;
}

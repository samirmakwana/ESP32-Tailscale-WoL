/**
 * @file microlink_disco_zerocopy.c
 * @brief DISCO protocol with zero-copy WireGuard injection (high-throughput mode)
 *
 * This implementation is contributed by dj-oyu (https://github.com/dj-oyu/microlink)
 * and is optimized for high-throughput applications like video streaming (30fps+).
 *
 * Uses a raw lwIP UDP PCB instead of a BSD socket. The PCB recv callback
 * runs in tcpip_thread and demultiplexes:
 *   - WireGuard packets → wireguardif_network_rx() directly (ZERO COPY)
 *   - DISCO packets → SPSC ring buffer for microlink task
 *   - STUN responses → dedicated buffer for STUN module
 *
 * Enable via: menuconfig → MicroLink Configuration → Enable zero-copy WireGuard receive
 *
 * For typical IoT/sensor applications (heartbeats, commands), the default
 * BSD socket mode (microlink_disco.c) is simpler and sufficient.
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
#include "nacl_box.h"
#include <string.h>

// lwIP raw API (PCB, pbuf, tcpip_callback)
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"

// WireGuard headers for zero-copy injection
#include "wireguardif.h"
#include "wireguard.h"

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

/* STUN magic cookie for identifying STUN responses in PCB callback */
#define STUN_MAGIC_COOKIE       0x2112A442

/* Timing */
#define DISCO_PROBE_INTERVAL_MS         5000   // 5 seconds between probes (searching for direct path)
#define DISCO_PROBE_INTERVAL_DIRECT_MS  30000  // 30 seconds when direct path is already established
#define DISCO_PROBE_TIMEOUT_MS          3000   // 3 second timeout for response
#define DISCO_STALE_THRESHOLD_MS        30000  // Consider path stale after 30s
#define DISCO_PONG_RATE_LIMIT_MS        5000   // Min interval between outgoing PONGs per peer

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

/* ============================================================================
 * Send Pool (SPSC: microlink task → tcpip thread)
 *
 * DISCO probes and PONGs are prepared by the microlink task but must be
 * sent via udp_sendto() which requires tcpip_thread context.
 * ========================================================================== */

#define DISCO_TX_POOL_SIZE 24  // Expanded for port-prediction probes

typedef struct {
    struct udp_pcb *pcb;
    uint8_t data[DISCO_MAX_PACKET_SIZE];
    uint16_t len;
    ip_addr_t dest;
    uint16_t port;
} disco_tx_ctx_t;

static disco_tx_ctx_t s_tx_pool[DISCO_TX_POOL_SIZE];
static volatile uint8_t s_tx_head = 0;  // Written by microlink task
static volatile uint8_t s_tx_tail = 0;  // Written by tcpip thread

static void disco_send_in_tcpip(void *arg) {
    disco_tx_ctx_t *ctx = (disco_tx_ctx_t *)arg;
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, ctx->len, PBUF_RAM);
    if (p) {
        memcpy(p->payload, ctx->data, ctx->len);
        udp_sendto(ctx->pcb, p, &ctx->dest, ctx->port);
        pbuf_free(p);
    }
    __atomic_store_n(&s_tx_tail, (uint8_t)((s_tx_tail + 1) % DISCO_TX_POOL_SIZE), __ATOMIC_RELEASE);
}

/* Forward declarations */
static esp_err_t disco_probe_via_derp(microlink_t *ml, uint8_t peer_idx);
static esp_err_t disco_process_packet(microlink_t *ml, const uint8_t *packet, size_t len,
                                      uint32_t src_ip, uint16_t src_port);

/* External: wireguardif_network_rx (for zero-copy WG packet injection) */
extern void wireguardif_network_rx(void *arg, struct udp_pcb *pcb,
                                    struct pbuf *p, const ip_addr_t *addr, u16_t port);

/**
 * @brief Check if peer is a WG-configured target (safe for handshake)
 */
static bool disco_is_target_peer(const microlink_t *ml, const microlink_peer_t *peer) {
    if (!ml->config.target_hostname) {
        return true;  // No filter - all peers are targets
    }
    return strncmp(peer->hostname, ml->config.target_hostname,
                   strlen(ml->config.target_hostname)) == 0;
}

/**
 * @brief Generate random bytes
 */
static void disco_random_bytes(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

/* ============================================================================
 * Raw lwIP PCB Receive Callback (runs in tcpip_thread)
 *
 * This is the core of the zero-copy optimization:
 * - WG packets → wireguardif_network_rx() directly (zero copy, same thread)
 * - DISCO packets → SPSC ring buffer for microlink task
 * - STUN responses → dedicated buffer for STUN module
 * ========================================================================== */

static void disco_pcb_recv_cb(void *arg, struct udp_pcb *pcb,
                               struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    microlink_t *ml = (microlink_t *)arg;
    if (!ml || !p) {
        if (p) pbuf_free(p);
        return;
    }

    uint8_t *data = (uint8_t *)p->payload;
    size_t len = p->tot_len;

    // 1. Check for DISCO magic header (6 bytes)
    bool is_disco = microlink_disco_is_disco_packet(data, len);

    // 2. Check for STUN response (magic cookie at bytes 4-7)
    bool is_stun = false;
    if (!is_disco && len >= 20) {
        uint32_t cookie = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
                          ((uint32_t)data[6] << 8) | (uint32_t)data[7];
        is_stun = (cookie == STUN_MAGIC_COOKIE);
    }

    if (is_disco) {
        // DISCO control packet → copy to ring buffer (small, rare)
        uint8_t head = __atomic_load_n(&ml->disco.rx_head, __ATOMIC_RELAXED);
        uint8_t next = (head + 1) % DISCO_RX_RING_SIZE;
        uint8_t tail = __atomic_load_n(&ml->disco.rx_tail, __ATOMIC_ACQUIRE);
        if (next != tail) {
            disco_rx_entry_t *entry = &ml->disco.rx_ring[head];
            entry->len = (len > DISCO_RX_MAX_PKT_SIZE) ? DISCO_RX_MAX_PKT_SIZE : len;
            pbuf_copy_partial(p, entry->data, entry->len, 0);
            entry->src_ip_nbo = ip_addr_get_ip4_u32(addr);
            entry->src_port = port;
            __atomic_store_n(&ml->disco.rx_head, next, __ATOMIC_RELEASE);
        }
        pbuf_free(p);
    } else if (is_stun) {
        // STUN response → dedicated buffer
        uint16_t copy_len = (len > sizeof(ml->disco.stun_resp_data))
                            ? sizeof(ml->disco.stun_resp_data) : len;
        pbuf_copy_partial(p, ml->disco.stun_resp_data, copy_len, 0);
        ml->disco.stun_resp_len = copy_len;
        __atomic_store_n(&ml->disco.stun_resp_ready, true, __ATOMIC_RELEASE);
        pbuf_free(p);
    } else if (ml->wireguard.initialized && ml->wireguard.netif) {
        // WG transport packet → ZERO COPY direct to WireGuard (same thread!)
        struct netif *wg_netif = (struct netif *)ml->wireguard.netif;
        struct wireguard_device *device = (struct wireguard_device *)wg_netif->state;
        if (device) {
            // wireguardif_network_rx takes ownership of pbuf and calls pbuf_free()
            wireguardif_network_rx(device, device->udp_pcb, p, addr, port);
            return;  // DO NOT free — WG owns the pbuf now
        }
        pbuf_free(p);
    } else {
        // Unknown packet, discard
        pbuf_free(p);
    }
}

/* ============================================================================
 * PCB Init/Deinit helpers (must run in tcpip_thread)
 * ========================================================================== */

typedef struct {
    struct udp_pcb *pcb;
    uint16_t port;
    microlink_t *ml;
    err_t result;
    SemaphoreHandle_t done;
} disco_pcb_setup_ctx_t;

static void disco_pcb_create_in_tcpip(void *arg) {
    disco_pcb_setup_ctx_t *ctx = (disco_pcb_setup_ctx_t *)arg;

    ctx->pcb = udp_new();
    if (!ctx->pcb) {
        ctx->result = ERR_MEM;
        xSemaphoreGive(ctx->done);
        return;
    }

    ctx->result = udp_bind(ctx->pcb, IP_ADDR_ANY, 0);
    if (ctx->result != ERR_OK) {
        udp_remove(ctx->pcb);
        ctx->pcb = NULL;
        xSemaphoreGive(ctx->done);
        return;
    }

    ctx->port = ctx->pcb->local_port;

    // Bind to WiFi netif (skip WG netif)
    extern struct netif *netif_list;
    for (struct netif *n = netif_list; n != NULL; n = n->next) {
        if (n != (struct netif *)ctx->ml->wireguard.netif) {
            udp_bind_netif(ctx->pcb, n);
            break;
        }
    }

    // Register receive callback
    udp_recv(ctx->pcb, disco_pcb_recv_cb, ctx->ml);

    xSemaphoreGive(ctx->done);
}

static void disco_pcb_remove_in_tcpip(void *arg) {
    disco_pcb_setup_ctx_t *ctx = (disco_pcb_setup_ctx_t *)arg;
    if (ctx->pcb) {
        udp_remove(ctx->pcb);
    }
    xSemaphoreGive(ctx->done);
}

/* ============================================================================
 * Packet Building (unchanged)
 * ========================================================================== */

/**
 * @brief Build DISCO ping packet
 */
static int disco_build_ping(microlink_t *ml, const microlink_peer_t *peer,
                            uint8_t *txid, uint8_t *packet) {
    disco_random_bytes(txid, DISCO_TXID_LEN);

    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    uint8_t plaintext[1 + 1 + DISCO_TXID_LEN + 32];
    int pt_offset = 0;
    plaintext[pt_offset++] = DISCO_MSG_PING;
    plaintext[pt_offset++] = 0;
    memcpy(plaintext + pt_offset, txid, DISCO_TXID_LEN);
    pt_offset += DISCO_TXID_LEN;
    memcpy(plaintext + pt_offset, ml->wireguard.public_key, 32);

    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];
    if (nacl_box(ciphertext, plaintext, sizeof(plaintext), nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "nacl_box encryption failed");
        return -1;
    }

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
 * @brief Build DISCO pong packet
 */
static int disco_build_pong(microlink_t *ml, const microlink_peer_t *peer,
                            const uint8_t *txid, uint32_t src_ip, uint16_t src_port,
                            uint8_t *packet) {
    ESP_LOGD(TAG, "Building PONG: src=%u.%u.%u.%u:%u",
             (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
             (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port);

    uint8_t nonce[DISCO_NONCE_LEN];
    disco_random_bytes(nonce, DISCO_NONCE_LEN);

    uint8_t plaintext[1 + 1 + DISCO_TXID_LEN + 18];
    int pt_offset = 0;
    plaintext[pt_offset++] = DISCO_MSG_PONG;
    plaintext[pt_offset++] = 0;
    memcpy(plaintext + pt_offset, txid, DISCO_TXID_LEN);
    pt_offset += DISCO_TXID_LEN;

    memset(plaintext + pt_offset, 0, 10);
    pt_offset += 10;
    plaintext[pt_offset++] = 0xff;
    plaintext[pt_offset++] = 0xff;
    plaintext[pt_offset++] = (src_ip >> 24) & 0xFF;
    plaintext[pt_offset++] = (src_ip >> 16) & 0xFF;
    plaintext[pt_offset++] = (src_ip >> 8) & 0xFF;
    plaintext[pt_offset++] = src_ip & 0xFF;
    plaintext[pt_offset++] = (src_port >> 8) & 0xFF;
    plaintext[pt_offset++] = src_port & 0xFF;

    uint8_t ciphertext[sizeof(plaintext) + DISCO_MAC_LEN];
    if (nacl_box(ciphertext, plaintext, sizeof(plaintext), nonce,
                 peer->disco_key, ml->wireguard.disco_private_key) != 0) {
        ESP_LOGE(TAG, "nacl_box encryption failed");
        return -1;
    }

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

/* ============================================================================
 * Send via PCB (fire-and-forget through tcpip_thread)
 * ========================================================================== */

/**
 * @brief Send a UDP packet through the DISCO PCB.
 *
 * Called from the microlink task.  The packet is placed in a send pool
 * and dispatched to the tcpip thread via tcpip_try_callback().
 *
 * @param dest_ip_nbo  Destination IP in network byte order
 * @param dest_port    Destination port in host byte order
 */
esp_err_t microlink_disco_sendto(microlink_t *ml, uint32_t dest_ip_nbo, uint16_t dest_port,
                                  const uint8_t *data, size_t len) {
    if (!ml->disco.pcb) {
        return ESP_ERR_INVALID_STATE;
    }
    if (len > DISCO_MAX_PACKET_SIZE) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t head = __atomic_load_n(&s_tx_head, __ATOMIC_RELAXED);
    uint8_t next = (head + 1) % DISCO_TX_POOL_SIZE;
    uint8_t tail = __atomic_load_n(&s_tx_tail, __ATOMIC_ACQUIRE);
    if (next == tail) {
        ESP_LOGW(TAG, "DISCO send pool full, dropping packet");
        return ESP_ERR_NO_MEM;
    }

    disco_tx_ctx_t *ctx = &s_tx_pool[head];
    ctx->pcb = (struct udp_pcb *)ml->disco.pcb;
    ctx->len = len;
    memcpy(ctx->data, data, len);
    ip_addr_set_any(false, &ctx->dest);
    ctx->dest.u_addr.ip4.addr = dest_ip_nbo;
    ctx->dest.type = IPADDR_TYPE_V4;
    ctx->port = dest_port;

    if (tcpip_try_callback(disco_send_in_tcpip, ctx) != ERR_OK) {
        return ESP_FAIL;
    }

    __atomic_store_n(&s_tx_head, next, __ATOMIC_RELEASE);
    return ESP_OK;
}

/* ============================================================================
 * Probe Sending
 * ========================================================================== */

static esp_err_t disco_probe_endpoint(microlink_t *ml, uint8_t peer_idx, uint8_t ep_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];
    microlink_endpoint_t *ep = &peer->endpoints[ep_idx];
    disco_probe_state_t *probe = &pending_probes[peer_idx][ep_idx];

    if (ep->is_derp) {
        return ESP_OK;
    }

    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return ESP_FAIL;
    }

    esp_err_t err = microlink_disco_sendto(ml, ep->addr.ip4, ep->port, packet, pkt_len);
    if (err != ESP_OK) {
        return err;
    }

    memcpy(probe->txid, txid, DISCO_TXID_LEN);
    probe->send_time_ms = microlink_get_time_ms();
    probe->pending = true;

    {
        uint32_t hip = ntohl(ep->addr.ip4);
        ESP_LOGD(TAG, "DISCO ping -> %lu.%lu.%lu.%lu:%d (peer %d ep %d)",
                 (unsigned long)(hip >> 24) & 0xFF, (unsigned long)(hip >> 16) & 0xFF,
                 (unsigned long)(hip >> 8) & 0xFF, (unsigned long)hip & 0xFF,
                 ep->port, peer_idx, ep_idx);
    }
    return ESP_OK;
}

/* ============================================================================
 * Packet Processing (runs in microlink task from ring buffer)
 * ========================================================================== */

static esp_err_t disco_process_packet(microlink_t *ml, const uint8_t *packet, size_t len,
                                      uint32_t src_ip, uint16_t src_port) {
    size_t min_len = DISCO_MAGIC_LEN + DISCO_KEY_LEN + DISCO_NONCE_LEN + DISCO_MAC_LEN + 1 + DISCO_TXID_LEN;
    if (len < min_len) {
        ESP_LOGD(TAG, "DISCO packet too short: %zu", len);
        return ESP_ERR_INVALID_SIZE;
    }

    if (memcmp(packet, DISCO_MAGIC, DISCO_MAGIC_LEN) != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    const uint8_t *sender_key = packet + DISCO_MAGIC_LEN;
    const uint8_t *nonce = packet + DISCO_MAGIC_LEN + DISCO_KEY_LEN;
    const uint8_t *ciphertext = nonce + DISCO_NONCE_LEN;
    size_t ciphertext_len = len - DISCO_MAGIC_LEN - DISCO_KEY_LEN - DISCO_NONCE_LEN;

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

    uint8_t plaintext[256];
    size_t plaintext_len = ciphertext_len - DISCO_MAC_LEN;
    if (plaintext_len > sizeof(plaintext)) {
        ESP_LOGW(TAG, "DISCO payload too large: %zu", plaintext_len);
        return ESP_ERR_NO_MEM;
    }

    int ret = nacl_box_open(plaintext, ciphertext, ciphertext_len,
                            nonce, sender_key, ml->wireguard.disco_private_key);
    if (ret != 0) {
        ESP_LOGE(TAG, "DISCO decryption failed");
        return ESP_ERR_INVALID_ARG;
    }

    if (plaintext_len < 1 + 1 + DISCO_TXID_LEN) {
        ESP_LOGD(TAG, "DISCO payload too short after decrypt: %zu", plaintext_len);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t msg_type = plaintext[0];
    uint8_t msg_version = plaintext[1];
    const uint8_t *txid = plaintext + 2;
    (void)msg_version;

    ESP_LOGD(TAG, "DISCO rx %s from peer %d (%s) src=%lu.%lu.%lu.%lu:%u",
             msg_type == DISCO_MSG_PING ? "PING" :
             msg_type == DISCO_MSG_PONG ? "PONG" :
             msg_type == DISCO_MSG_CALL_ME_MAYBE ? "CALL_ME_MAYBE" : "UNKNOWN",
             peer_idx, peer->hostname,
             (unsigned long)(src_ip >> 24) & 0xFF, (unsigned long)(src_ip >> 16) & 0xFF,
             (unsigned long)(src_ip >> 8) & 0xFF, (unsigned long)src_ip & 0xFF,
             src_port);

    switch (msg_type) {
        case DISCO_MSG_PING: {
            // Direct PINGs prove path liveness — update last_seen_ms
            if (src_ip != 0) {
                peer->last_seen_ms = (uint32_t)microlink_get_time_ms();
            }

            ESP_LOGD(TAG, "PING from peer %d (%s)", peer_idx, peer->hostname);

            // Rate-limit PONG responses when direct path is established.
            // Always respond immediately when searching (using_derp) or first time.
            uint64_t now_pong = microlink_get_time_ms();
            uint64_t last_pong = ml->disco.peer_disco[peer_idx].last_pong_sent_ms;
            bool should_respond = peer->using_derp ||
                                  last_pong == 0 ||
                                  (now_pong - last_pong) >= DISCO_PONG_RATE_LIMIT_MS;

            if (!should_respond) {
                ESP_LOGD(TAG, "PONG rate-limited for peer %d", peer_idx);
                break;
            }

            uint8_t pong[DISCO_MAX_PACKET_SIZE];
            uint32_t pong_src_ip = src_ip;
            uint16_t pong_src_port = src_port;
            if (pong_src_ip == 0) {
                pong_src_ip = ml->vpn_ip;
                pong_src_port = 0;
            }
            int pong_len = disco_build_pong(ml, peer, txid, pong_src_ip, pong_src_port, pong);
            if (pong_len > 0) {
                if (src_ip == 0) {
                    esp_err_t err = microlink_derp_send(ml, peer->vpn_ip, pong, pong_len);
                    if (err == ESP_OK) {
                        ESP_LOGD(TAG, "PONG sent via DERP to peer %d", peer_idx);
                        ml->disco.peer_disco[peer_idx].last_pong_sent_ms = now_pong;
                    } else {
                        ESP_LOGE(TAG, "Failed to send PONG via DERP: %s", esp_err_to_name(err));
                    }
                } else {
                    // src_ip is host byte order; sendto expects network byte order
                    microlink_disco_sendto(ml, htonl(src_ip), src_port, pong, pong_len);
                    ESP_LOGD(TAG, "PONG sent to peer %d", peer_idx);
                    ml->disco.peer_disco[peer_idx].last_pong_sent_ms = now_pong;
                }
            } else {
                ESP_LOGE(TAG, "Failed to build PONG");
            }
            break;
        }

        case DISCO_MSG_PONG: {
            uint64_t now = microlink_get_time_ms();
            bool found = false;
            bool via_derp = (src_ip == 0);

            for (int ep = 0; ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                disco_probe_state_t *probe = &pending_probes[peer_idx][ep];
                if (probe->pending && memcmp(probe->txid + 1, txid + 1, DISCO_TXID_LEN - 1) == 0) {
                    uint32_t rtt = (uint32_t)(now - probe->send_time_ms);
                    probe->pending = false;
                    found = true;

                    bool is_derp_slot = (ep == MICROLINK_MAX_ENDPOINTS - 1);

                    if (is_derp_slot || via_derp) {
                        ESP_LOGD(TAG, "PONG peer %d via DERP: %lums", peer_idx, (unsigned long)rtt);
                        if (peer->using_derp) {
                            if (peer->latency_ms == 0 || rtt < peer->latency_ms) {
                                peer->latency_ms = rtt;
                                peer->best_endpoint_idx = ep;
                            }
                        }
                    } else {
                        ESP_LOGD(TAG, "PONG peer %d direct: %lums src=%lu.%lu.%lu.%lu:%u",
                                 peer_idx, (unsigned long)rtt,
                                 (unsigned long)(src_ip >> 24) & 0xFF,
                                 (unsigned long)(src_ip >> 16) & 0xFF,
                                 (unsigned long)(src_ip >> 8) & 0xFF,
                                 (unsigned long)src_ip & 0xFF, src_port);
                        peer->latency_ms = rtt;
                        peer->best_endpoint_idx = ep;
                        // Ensure WG connect_ip/connect_port are in sync
                        // (update_peer_addr() already handles ip/port on rx)
                        microlink_wireguard_update_endpoint(
                            ml, peer->vpn_ip, src_ip, src_port);
                        peer->using_derp = false;
                    }

                    peer->last_seen_ms = now;
                    break;
                }
            }

            if (!found) {
                if (!via_derp) {
                    // Check full txid match (CMM/spray probes)
                    bool full_match = false;
                    for (int ep = 0; ep < MICROLINK_MAX_ENDPOINTS; ep++) {
                        disco_probe_state_t *probe = &pending_probes[peer_idx][ep];
                        if (probe->pending && memcmp(probe->txid, txid, DISCO_TXID_LEN) == 0) {
                            uint32_t rtt = (uint32_t)(now - probe->send_time_ms);
                            probe->pending = false;
                            full_match = true;

                            ESP_LOGI(TAG, "Hole-punch success! Peer %d RTT=%lums", peer_idx, (unsigned long)rtt);
                            microlink_wireguard_update_endpoint(ml, peer->vpn_ip, src_ip, src_port);

                            peer->latency_ms = rtt;
                            peer->last_seen_ms = now;
                            peer->using_derp = false;
                            break;
                        }
                    }

                    // Unmatched direct PONG from a known peer — likely a spray/CMM probe
                    // that wasn't registered. Accept it as a successful hole-punch.
                    if (!full_match && peer->using_derp) {
                        ESP_LOGI(TAG, "Spray hole-punch success! Peer %d src=%lu.%lu.%lu.%lu:%u",
                                 peer_idx,
                                 (unsigned long)(src_ip >> 24) & 0xFF,
                                 (unsigned long)(src_ip >> 16) & 0xFF,
                                 (unsigned long)(src_ip >> 8) & 0xFF,
                                 (unsigned long)src_ip & 0xFF, src_port);
                        microlink_wireguard_update_endpoint(ml, peer->vpn_ip, src_ip, src_port);
                        peer->last_seen_ms = now;
                        peer->using_derp = false;
                    }
                } else {
                    peer->last_seen_ms = now;
                }
            }
            break;
        }

        case DISCO_MSG_CALL_ME_MAYBE: {
            ml->disco.peer_disco[peer_idx].active = true;

            // Skip probing if direct path is fresh — no need for hole-punch
            if (!peer->using_derp && peer->last_seen_ms > 0) {
                uint64_t now_cmm = microlink_get_time_ms();
                uint64_t age = now_cmm - (uint64_t)peer->last_seen_ms;
                if (age < DISCO_STALE_THRESHOLD_MS / 2) {
                    ESP_LOGD(TAG, "CMM from peer %d ignored: direct path fresh (%lums ago)",
                             peer_idx, (unsigned long)age);
                    break;
                }
            }

            // Parse endpoint list from CallMeMaybe payload
            // Format after type+version: N × 18 bytes (16B IPv4-mapped-IPv6 + 2B port BE)
            const size_t cmm_header = 1 + 1;  // type + version (no txid in CallMeMaybe)
            const size_t ep_size = 18;  // 16-byte IP + 2-byte port
            const uint8_t *ep_data = plaintext + cmm_header;
            size_t ep_data_len = plaintext_len - cmm_header;
            int ep_count = (ep_data_len >= ep_size) ? (int)(ep_data_len / ep_size) : 0;

            ESP_LOGI(TAG, "CallMeMaybe from peer %d (%s): %d candidate endpoints",
                     peer_idx, peer->hostname, ep_count);

            if (ep_count == 0) {
                break;
            }

            // Send DISCO ping to each CMM endpoint WITHOUT overwriting peer->endpoints.
            // Peer endpoints from coordination server are valuable and must be preserved.
            // PONGs from CMM probes will be handled by the "spray hole-punch" fallback
            // in the PONG handler (unmatched direct PONG from known peer).
            int probes_sent = 0;
            for (int ep = 0; ep < ep_count && probes_sent < MICROLINK_MAX_ENDPOINTS - 1; ep++) {
                const uint8_t *entry = ep_data + (ep * ep_size);

                // Check for IPv4-mapped IPv6: bytes 10-11 = 0xFF 0xFF, bytes 0-9 = 0x00
                bool is_v4 = true;
                for (int j = 0; j < 10; j++) {
                    if (entry[j] != 0) { is_v4 = false; break; }
                }
                if (entry[10] != 0xFF || entry[11] != 0xFF) is_v4 = false;

                if (!is_v4) {
                    ESP_LOGD(TAG, "  CMM ep[%d]: IPv6 (skipped)", ep);
                    continue;
                }

                // Extract IPv4 address (bytes 12-15) and port (bytes 16-17, big-endian)
                uint32_t ip_hbo = ((uint32_t)entry[12] << 24) | ((uint32_t)entry[13] << 16) |
                                  ((uint32_t)entry[14] << 8) | entry[15];
                uint16_t port = ((uint16_t)entry[16] << 8) | entry[17];
                uint32_t ip_nbo = htonl(ip_hbo);

                ESP_LOGI(TAG, "  CMM ep[%d]: %lu.%lu.%lu.%lu:%u",
                         ep,
                         (unsigned long)entry[12], (unsigned long)entry[13],
                         (unsigned long)entry[14], (unsigned long)entry[15],
                         port);

                // Build and send DISCO ping directly (don't store in peer->endpoints)
                uint8_t ping_pkt[DISCO_MAX_PACKET_SIZE];
                uint8_t ping_txid[DISCO_TXID_LEN];
                int pkt_len = disco_build_ping(ml, peer, ping_txid, ping_pkt);
                if (pkt_len > 0) {
                    esp_err_t send_err = microlink_disco_sendto(ml, ip_nbo, port,
                                                                 ping_pkt, pkt_len);
                    if (send_err == ESP_OK) {
                        probes_sent++;
                    }
                }
            }

            ESP_LOGI(TAG, "CallMeMaybe: sent %d probes to peer %d", probes_sent, peer_idx);
            break;
        }

        default:
            ESP_LOGD(TAG, "Unknown DISCO message type: 0x%02x", msg_type);
            break;
    }

    return ESP_OK;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

esp_err_t microlink_disco_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing DISCO protocol (raw PCB mode)");

    memset(&ml->disco, 0, sizeof(microlink_disco_t));
    memset(pending_probes, 0, sizeof(pending_probes));
    s_tx_head = 0;
    s_tx_tail = 0;

    // Create raw lwIP UDP PCB in tcpip_thread (required for thread safety)
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (!done) {
        ESP_LOGE(TAG, "Failed to create init semaphore");
        return ESP_ERR_NO_MEM;
    }

    disco_pcb_setup_ctx_t ctx = {
        .pcb = NULL,
        .port = 0,
        .ml = ml,
        .result = ERR_MEM,
        .done = done,
    };

    err_t cb_err = tcpip_callback(disco_pcb_create_in_tcpip, &ctx);
    if (cb_err != ERR_OK) {
        ESP_LOGE(TAG, "tcpip_callback failed: %d", cb_err);
        vSemaphoreDelete(done);
        return ESP_FAIL;
    }

    xSemaphoreTake(done, portMAX_DELAY);
    vSemaphoreDelete(done);

    if (ctx.result != ERR_OK || !ctx.pcb) {
        ESP_LOGE(TAG, "Failed to create DISCO PCB: lwIP error %d", ctx.result);
        return ESP_FAIL;
    }

    ml->disco.pcb = ctx.pcb;
    ml->disco.port = ctx.port;

    ESP_LOGI(TAG, "DISCO PCB bound to port %u (zero-copy WG receive enabled)", ctx.port);
    return ESP_OK;
}

esp_err_t microlink_disco_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing DISCO protocol");

    if (ml->disco.pcb) {
        SemaphoreHandle_t done = xSemaphoreCreateBinary();
        if (done) {
            disco_pcb_setup_ctx_t ctx = {
                .pcb = (struct udp_pcb *)ml->disco.pcb,
                .done = done,
            };
            if (tcpip_callback(disco_pcb_remove_in_tcpip, &ctx) == ERR_OK) {
                xSemaphoreTake(done, portMAX_DELAY);
            }
            vSemaphoreDelete(done);
        }
        ml->disco.pcb = NULL;
    }

    memset(&ml->disco, 0, sizeof(microlink_disco_t));
    memset(pending_probes, 0, sizeof(pending_probes));
    s_tx_head = 0;
    s_tx_tail = 0;

    ESP_LOGI(TAG, "DISCO deinitialized");
    return ESP_OK;
}

esp_err_t microlink_disco_probe_peers(microlink_t *ml) {
    uint64_t now = microlink_get_time_ms();

    if (now - ml->disco.last_global_disco_ms < DISCO_PROBE_INTERVAL_MS) {
        return ESP_OK;
    }
    ml->disco.last_global_disco_ms = now;

    for (uint8_t i = 0; i < ml->peer_count; i++) {
        microlink_peer_t *peer = &ml->peers[i];

        if (ml->config.target_hostname &&
            strncmp(peer->hostname, ml->config.target_hostname,
                    strlen(ml->config.target_hostname)) != 0) {
            continue;
        }

        // Use longer interval when direct path is already established
        uint64_t interval = (peer->using_derp || peer->last_seen_ms == 0)
                            ? DISCO_PROBE_INTERVAL_MS
                            : DISCO_PROBE_INTERVAL_DIRECT_MS;
        if (now - ml->disco.peer_disco[i].last_probe_ms < interval) {
            continue;
        }

        if (peer->using_derp) {
            ESP_LOGI(TAG, "DISCO probe peer %d (%s) [searching]", i, peer->hostname);
        } else {
            ESP_LOGD(TAG, "DISCO probe peer %d (%s) [maintenance]", i, peer->hostname);
        }

        for (uint8_t ep = 0; ep < peer->endpoint_count; ep++) {
            disco_probe_endpoint(ml, i, ep);
        }

        // Port-neighborhood spray when peer is still on DERP and has known endpoints.
        // We can't know the peer's NAT allocation pattern, so spray ±256 ports
        // around each known endpoint with step=1 (birthday-attack style).
        // This gives a ~1-2% chance per round with 16 probes if the peer's NAT
        // allocates sequentially within a ~1000-port window.
        if (peer->using_derp && peer->endpoint_count > 0) {
            int spray_count = 0;
            for (uint8_t ep = 0; ep < peer->endpoint_count && spray_count < 16; ep++) {
                if (peer->endpoints[ep].is_derp) continue;
                uint16_t base_port = peer->endpoints[ep].port;
                uint32_t ep_ip = peer->endpoints[ep].addr.ip4;
                // Spray ±8 ports around the known endpoint (step=1)
                for (int offset = -8; offset <= 8 && spray_count < 16; offset++) {
                    if (offset == 0) continue;  // Already probed by normal path
                    int predicted = (int)base_port + offset;
                    if (predicted < 1024 || predicted > 65535) continue;
                    uint8_t pkt[DISCO_MAX_PACKET_SIZE];
                    uint8_t spray_txid[DISCO_TXID_LEN];
                    int pkt_len = disco_build_ping(ml, peer, spray_txid, pkt);
                    if (pkt_len > 0) {
                        if (microlink_disco_sendto(ml, ep_ip, (uint16_t)predicted,
                                                    pkt, pkt_len) == ESP_OK) {
                            spray_count++;
                        }
                    }
                }
            }
            if (spray_count > 0) {
                ESP_LOGI(TAG, "DISCO port-spray: sent %d probes around %d known endpoints",
                         spray_count, peer->endpoint_count);
            }
        }

        disco_probe_via_derp(ml, i);

        ml->disco.peer_disco[i].last_probe_ms = now;
        ml->disco.peer_disco[i].probe_sequence++;
        ml->disco.peer_disco[i].active = true;
    }

    return ESP_OK;
}

/**
 * @brief Drain DISCO ring buffer and process control packets.
 *
 * WG transport packets never enter the ring buffer — they are delivered
 * directly to wireguardif_network_rx() in the PCB recv callback (zero-copy).
 * This function only handles DISCO PING/PONG/CallMeMaybe.
 */
esp_err_t microlink_disco_receive(microlink_t *ml) {
    if (!ml->disco.pcb) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t tail = __atomic_load_n(&ml->disco.rx_tail, __ATOMIC_RELAXED);
    uint8_t head = __atomic_load_n(&ml->disco.rx_head, __ATOMIC_ACQUIRE);

    while (tail != head) {
        disco_rx_entry_t *entry = &ml->disco.rx_ring[tail];

        uint32_t src_ip = ntohl(entry->src_ip_nbo);
        uint16_t src_port = entry->src_port;

        disco_process_packet(ml, entry->data, entry->len, src_ip, src_port);

        tail = (tail + 1) % DISCO_RX_RING_SIZE;
        __atomic_store_n(&ml->disco.rx_tail, tail, __ATOMIC_RELEASE);

        head = __atomic_load_n(&ml->disco.rx_head, __ATOMIC_ACQUIRE);
    }

    return ESP_OK;
}

esp_err_t microlink_disco_update_paths(microlink_t *ml) {
    if (!ml->disco.pcb) {
        return ESP_ERR_INVALID_STATE;
    }

    // Process any pending DISCO packets first
    microlink_disco_receive(ml);

    uint64_t now = microlink_get_time_ms();

    for (uint8_t i = 0; i < ml->peer_count; i++) {
        microlink_peer_t *peer = &ml->peers[i];

        for (uint8_t ep = 0; ep < peer->endpoint_count; ep++) {
            disco_probe_state_t *probe = &pending_probes[i][ep];
            if (probe->pending && (now - probe->send_time_ms) > DISCO_PROBE_TIMEOUT_MS) {
                probe->pending = false;
                ESP_LOGD(TAG, "DISCO probe timeout: peer %d endpoint %d", i, ep);
            }
        }

        if (peer->last_seen_ms > 0 && (now - peer->last_seen_ms) > DISCO_STALE_THRESHOLD_MS) {
            ESP_LOGW(TAG, "Peer %d path stale (no response in %lums)",
                     i, (unsigned long)(now - peer->last_seen_ms));
            // Reset to DERP mode → aggressive 5s probing + port spray
            if (!peer->using_derp) {
                ESP_LOGI(TAG, "Peer %d: direct path lost, reverting to DERP", i);
                peer->using_derp = true;
                // Reset WG endpoint to DERP relay and re-handshake
                if (ml->wireguard.netif) {
                    uint8_t last_byte = peer->vpn_ip & 0xFF;
                    if (last_byte < MICROLINK_PEER_MAP_SIZE) {
                        uint8_t wg_idx = ml->peer_map[last_byte];
                        if (wg_idx != 0xFF) {
                            wireguardif_connect_derp((struct netif *)ml->wireguard.netif, wg_idx);
                        }
                    }
                }
            }
        }
    }

    return ESP_OK;
}

static esp_err_t disco_probe_via_derp(microlink_t *ml, uint8_t peer_idx) {
    microlink_peer_t *peer = &ml->peers[peer_idx];

    if (!ml->derp.connected) {
        ESP_LOGD(TAG, "DERP not connected, skipping DERP probe");
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t packet[DISCO_MAX_PACKET_SIZE];
    uint8_t txid[DISCO_TXID_LEN];
    int pkt_len = disco_build_ping(ml, peer, txid, packet);
    if (pkt_len < 0) {
        return ESP_FAIL;
    }

    esp_err_t err = microlink_derp_send(ml, peer->vpn_ip, packet, pkt_len);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Failed to send DISCO via DERP: %d", err);
        return err;
    }

    disco_probe_state_t *probe = &pending_probes[peer_idx][MICROLINK_MAX_ENDPOINTS - 1];
    memcpy(probe->txid, txid, DISCO_TXID_LEN);
    probe->send_time_ms = microlink_get_time_ms();
    probe->pending = true;

    ESP_LOGD(TAG, "DISCO ping via DERP to peer %d (%s)", peer_idx, peer->hostname);
    return ESP_OK;
}

esp_err_t microlink_disco_handle_derp_packet(microlink_t *ml, const uint8_t *src_key,
                                              const uint8_t *data, size_t len) {
    if (len < DISCO_MAGIC_LEN || memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) != 0) {
        return ESP_ERR_INVALID_ARG;
    }

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

    if (len >= DISCO_MAGIC_LEN + DISCO_KEY_LEN) {
        const uint8_t *disco_sender_key = data + DISCO_MAGIC_LEN;
        microlink_peer_t *peer = &ml->peers[peer_idx];
        if (memcmp(peer->disco_key, disco_sender_key, 32) != 0) {
            ESP_LOGI(TAG, "Peer %d disco_key updated", peer_idx);
            memcpy(peer->disco_key, disco_sender_key, 32);
        }
    }

    return disco_process_packet(ml, data, len, 0, 0);
}

bool microlink_disco_is_disco_packet(const uint8_t *data, size_t len) {
    return (len >= DISCO_MAGIC_LEN && memcmp(data, DISCO_MAGIC, DISCO_MAGIC_LEN) == 0);
}

esp_err_t microlink_disco_handle_direct_packet(microlink_t *ml, const uint8_t *data, size_t len,
                                                uint32_t src_ip, uint16_t src_port) {
    if (!microlink_disco_is_disco_packet(data, len)) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "DISCO packet received on WG port from %lu.%lu.%lu.%lu:%u",
             (unsigned long)(src_ip >> 24) & 0xFF, (unsigned long)(src_ip >> 16) & 0xFF,
             (unsigned long)(src_ip >> 8) & 0xFF, (unsigned long)src_ip & 0xFF, src_port);
    return disco_process_packet(ml, data, len, src_ip, src_port);
}

/* ============================================================================
 * CallMeMaybe — tell peer to initiate handshake (from upstream v1.2.0)
 * ========================================================================== */

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
    uint8_t plaintext[2 + 3 * 18];  // type + version + up to 3 endpoints
    int pt_offset = 0;
    int endpoint_count = 0;

    plaintext[pt_offset++] = DISCO_MSG_CALL_ME_MAYBE;  // type
    plaintext[pt_offset++] = 0;                         // version = 0

    // Get local LAN IP from WiFi interface
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            uint32_t local_ip = ntohl(ip_info.ip.addr);
            uint16_t local_port = ml->disco.local_port;

            // Add local LAN endpoint (IPv6-mapped-IPv4 format)
            memset(plaintext + pt_offset, 0, 10);
            pt_offset += 10;
            plaintext[pt_offset++] = 0xff;
            plaintext[pt_offset++] = 0xff;
            plaintext[pt_offset++] = (local_ip >> 24) & 0xFF;
            plaintext[pt_offset++] = (local_ip >> 16) & 0xFF;
            plaintext[pt_offset++] = (local_ip >> 8) & 0xFF;
            plaintext[pt_offset++] = local_ip & 0xFF;
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
        memset(plaintext + pt_offset, 0, 10);
        pt_offset += 10;
        plaintext[pt_offset++] = 0xff;
        plaintext[pt_offset++] = 0xff;
        plaintext[pt_offset++] = (ml->stun.public_ip >> 24) & 0xFF;
        plaintext[pt_offset++] = (ml->stun.public_ip >> 16) & 0xFF;
        plaintext[pt_offset++] = (ml->stun.public_ip >> 8) & 0xFF;
        plaintext[pt_offset++] = ml->stun.public_ip & 0xFF;
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

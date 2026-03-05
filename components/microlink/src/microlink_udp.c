/**
 * @file microlink_udp.c
 * @brief MicroLink UDP Socket API
 *
 * Provides simple UDP send/receive over Tailscale VPN, equivalent to:
 *   echo "data" | nc -u <tailscale_ip> <port>
 *
 * This implementation routes UDP through the existing MicroLink infrastructure:
 * - Uses WireGuard tunnel for encrypted transport (standard Tailscale path)
 * - Automatically sends DISCO CallMeMaybe to trigger peer handshake initiation
 * - Dedicated high-priority RX task for consistent packet reception
 *
 * Handshake Strategy:
 * ESP32-initiated WireGuard handshakes may not complete due to NAT/firewall
 * asymmetry. To work around this, we send DISCO CallMeMaybe messages which
 * tell the peer "please initiate a connection to me". When the peer (e.g., PC)
 * initiates the handshake, it completes successfully, enabling bidirectional
 * UDP communication.
 */

#include "microlink.h"
#include "microlink_internal.h"
#include "esp_log.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

static const char *TAG = "ml_udp";

/* High-priority UDP RX task settings */
#define UDP_RX_TASK_PRIORITY    (configMAX_PRIORITIES - 2)  /* Just below DISCO */
#define UDP_RX_TASK_STACK_SIZE  4096
#define UDP_RX_POLL_INTERVAL_MS 5  /* Fast polling for low latency */

/* ============================================================================
 * UDP Socket Structure
 * ========================================================================== */

#define UDP_RX_QUEUE_SIZE 4
#define UDP_MAX_PACKET_SIZE 1400

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint8_t data[UDP_MAX_PACKET_SIZE];
    size_t len;
    bool valid;
} udp_rx_packet_t;

struct microlink_udp_socket {
    microlink_t *ml;                    ///< Parent MicroLink context
    struct udp_pcb *pcb;                ///< lwIP UDP PCB (for receiving)
    uint16_t local_port;                ///< Local bound port

    // RX queue for received packets
    udp_rx_packet_t rx_queue[UDP_RX_QUEUE_SIZE];
    volatile uint8_t rx_head;
    volatile uint8_t rx_tail;

    // Semaphore for RX notification (callback -> task)
    SemaphoreHandle_t rx_sem;

    // User callback for immediate packet handling
    microlink_udp_rx_callback_t rx_callback;
    void *rx_callback_arg;

    // RX task handle
    TaskHandle_t rx_task_handle;
    volatile bool rx_task_running;
};

/* ============================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * @brief Convert MicroLink IP (host byte order) to lwIP ip_addr_t
 */
static void microlink_ip_to_lwip(uint32_t ml_ip, ip_addr_t *lwip_ip) {
    IP4_ADDR(&lwip_ip->u_addr.ip4,
             (ml_ip >> 24) & 0xFF,
             (ml_ip >> 16) & 0xFF,
             (ml_ip >> 8) & 0xFF,
             ml_ip & 0xFF);
    lwip_ip->type = IPADDR_TYPE_V4;
}

/**
 * @brief Convert lwIP ip_addr_t to MicroLink IP (host byte order)
 */
static uint32_t lwip_ip_to_microlink(const ip_addr_t *lwip_ip) {
    if (lwip_ip->type != IPADDR_TYPE_V4) {
        return 0;
    }

    uint32_t ip = ip4_addr_get_u32(&lwip_ip->u_addr.ip4);
    return ((ip & 0xFF) << 24) |
           (((ip >> 8) & 0xFF) << 16) |
           (((ip >> 16) & 0xFF) << 8) |
           ((ip >> 24) & 0xFF);
}

/**
 * @brief lwIP UDP receive callback - runs from tcpip thread
 *
 * Queues the packet and signals the semaphore for the RX task.
 * Must be fast and avoid blocking!
 */
static void udp_recv_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                               const ip_addr_t *addr, u16_t port) {
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;

    if (!sock || !p) {
        if (p) pbuf_free(p);
        return;
    }

    // Check if queue is full
    uint8_t next_head = (sock->rx_head + 1) % UDP_RX_QUEUE_SIZE;
    if (next_head == sock->rx_tail) {
        ESP_LOGW(TAG, "RX queue full, dropping packet");
        pbuf_free(p);
        return;
    }

    // Copy packet to queue
    udp_rx_packet_t *pkt = &sock->rx_queue[sock->rx_head];
    pkt->src_ip = lwip_ip_to_microlink(addr);
    pkt->src_port = port;
    pkt->len = (p->tot_len > UDP_MAX_PACKET_SIZE) ? UDP_MAX_PACKET_SIZE : p->tot_len;
    pbuf_copy_partial(p, pkt->data, pkt->len, 0);
    pkt->valid = true;

    // Memory barrier before updating head
    __sync_synchronize();
    sock->rx_head = next_head;

    // Signal RX task that packet is available
    // NOTE: lwIP UDP callback runs from tcpip thread, NOT from ISR
    // Use regular xSemaphoreGive, not xSemaphoreGiveFromISR
    if (sock->rx_sem) {
        xSemaphoreGive(sock->rx_sem);
    }

    pbuf_free(p);
}

/**
 * @brief Dedicated UDP RX task - high priority for consistent reception
 *
 * This task waits on the semaphore and immediately processes received packets.
 * Running at high priority ensures packets are handled promptly without being
 * starved by other tasks.
 */
static void udp_rx_task(void *arg) {
    microlink_udp_socket_t *sock = (microlink_udp_socket_t *)arg;

    ESP_LOGI(TAG, "[UDP_RX] Task started, priority=%d", uxTaskPriorityGet(NULL));

    while (sock->rx_task_running) {
        // Wait for packet notification (with timeout for task shutdown check)
        if (xSemaphoreTake(sock->rx_sem, pdMS_TO_TICKS(100)) == pdTRUE) {
            // Process all queued packets
            while (sock->rx_tail != sock->rx_head) {
                udp_rx_packet_t *pkt = &sock->rx_queue[sock->rx_tail];

                if (pkt->valid) {
                    char ip_buf[16];
                    ESP_LOGI(TAG, "[UDP_RX] Packet: %u bytes from %s:%u",
                             (unsigned int)pkt->len,
                             microlink_vpn_ip_to_str(pkt->src_ip, ip_buf),
                             pkt->src_port);

                    // Call user callback if registered
                    if (sock->rx_callback) {
                        sock->rx_callback(sock, pkt->src_ip, pkt->src_port,
                                          pkt->data, pkt->len, sock->rx_callback_arg);
                    }
                }

                // Note: Don't mark as invalid here - let microlink_udp_recv() handle it
                // for users who prefer polling instead of callbacks

                // If no callback, just log and move on (user can poll with microlink_udp_recv)
                if (!sock->rx_callback) {
                    // Packet stays in queue for polling
                    break;
                } else {
                    // Callback consumed it, advance tail
                    pkt->valid = false;
                    sock->rx_tail = (sock->rx_tail + 1) % UDP_RX_QUEUE_SIZE;
                }
            }
        }
    }

    ESP_LOGI(TAG, "[UDP_RX] Task exiting");
    vTaskDelete(NULL);
}

/* ============================================================================
 * Public API Implementation
 * ========================================================================== */

uint32_t microlink_parse_ip(const char *ip_str) {
    if (!ip_str) return 0;

    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        ESP_LOGE(TAG, "Invalid IP format: %s", ip_str);
        return 0;
    }

    if (a > 255 || b > 255 || c > 255 || d > 255) {
        ESP_LOGE(TAG, "IP octet out of range: %s", ip_str);
        return 0;
    }

    return (a << 24) | (b << 16) | (c << 8) | d;
}

microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port) {
    if (!ml) {
        ESP_LOGE(TAG, "NULL MicroLink handle");
        return NULL;
    }

    if (!microlink_is_connected(ml)) {
        ESP_LOGE(TAG, "MicroLink not connected");
        return NULL;
    }

    // Allocate socket structure
    microlink_udp_socket_t *sock = calloc(1, sizeof(microlink_udp_socket_t));
    if (!sock) {
        ESP_LOGE(TAG, "Failed to allocate UDP socket");
        return NULL;
    }

    sock->ml = ml;
    sock->rx_head = 0;
    sock->rx_tail = 0;
    sock->rx_callback = NULL;
    sock->rx_callback_arg = NULL;
    sock->rx_task_handle = NULL;
    sock->rx_task_running = false;

    // Create counting semaphore for RX notification
    // Use counting semaphore (not binary) so multiple packet arrivals don't lose signals
    sock->rx_sem = xSemaphoreCreateCounting(UDP_RX_QUEUE_SIZE, 0);
    if (!sock->rx_sem) {
        ESP_LOGE(TAG, "Failed to create RX semaphore");
        free(sock);
        return NULL;
    }

    // Create lwIP UDP PCB for receiving
    sock->pcb = udp_new();
    if (!sock->pcb) {
        ESP_LOGE(TAG, "Failed to create UDP PCB");
        vSemaphoreDelete(sock->rx_sem);
        free(sock);
        return NULL;
    }

    // Bind to WireGuard netif if available
    if (ml->wireguard.netif) {
        udp_bind_netif(sock->pcb, (struct netif *)ml->wireguard.netif);
    }

    // Bind to local IP and port
    ip_addr_t local_ip;
    microlink_ip_to_lwip(ml->vpn_ip, &local_ip);

    err_t err = udp_bind(sock->pcb, &local_ip, local_port);
    if (err != ERR_OK) {
        ESP_LOGE(TAG, "udp_bind() failed: %d", err);
        udp_remove(sock->pcb);
        vSemaphoreDelete(sock->rx_sem);
        free(sock);
        return NULL;
    }

    sock->local_port = sock->pcb->local_port;

    // Set receive callback
    udp_recv(sock->pcb, udp_recv_callback, sock);

    // Start dedicated RX task for consistent packet handling
    sock->rx_task_running = true;
    BaseType_t task_ret = xTaskCreatePinnedToCore(
        udp_rx_task,
        "udp_rx",
        UDP_RX_TASK_STACK_SIZE,
        sock,
        UDP_RX_TASK_PRIORITY,
        &sock->rx_task_handle,
        1  /* Pin to Core 1 to avoid blocking Core 0 WiFi/lwIP */
    );

    if (task_ret != pdPASS) {
        ESP_LOGW(TAG, "Failed to create RX task, falling back to polling mode");
        sock->rx_task_running = false;
    } else {
        ESP_LOGI(TAG, "UDP RX task started (priority=%d, core=1)", UDP_RX_TASK_PRIORITY);
    }

    char ip_buf[16];
    ESP_LOGI(TAG, "UDP socket created: %s:%u",
             microlink_vpn_ip_to_str(ml->vpn_ip, ip_buf), sock->local_port);

    // Aggressively establish WireGuard sessions with all peers
    // Use BOTH approaches: trigger handshake from our side AND send CallMeMaybe
    // This ensures bidirectional communication works regardless of who initiates
    ESP_LOGI(TAG, "Establishing WireGuard sessions with %d peers...", ml->peer_count);
    for (int i = 0; i < ml->peer_count; i++) {
        uint32_t peer_ip = ml->peers[i].vpn_ip;

        // 1. Trigger WireGuard handshake from ESP32 side
        esp_err_t hs_err = microlink_wireguard_trigger_handshake(ml, peer_ip);
        if (hs_err == ESP_OK) {
            ESP_LOGI(TAG, "  -> Handshake triggered to peer %d (%s)",
                     i, microlink_vpn_ip_to_str(peer_ip, ip_buf));
        }

        // 2. Also send CallMeMaybe to request peer initiate handshake
        // This covers the case where our handshake doesn't complete (NAT issues)
        esp_err_t cmm_err = microlink_disco_send_call_me_maybe(ml, peer_ip);
        if (cmm_err == ESP_OK) {
            ESP_LOGI(TAG, "  -> CallMeMaybe sent to peer %d (%s)",
                     i, microlink_vpn_ip_to_str(peer_ip, ip_buf));
        }

        // Small delay between peers to avoid overwhelming the network
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    return sock;
}

void microlink_udp_close(microlink_udp_socket_t *sock) {
    if (!sock) return;

    // Stop RX task first
    if (sock->rx_task_running) {
        sock->rx_task_running = false;
        // Give semaphore to wake task for shutdown check
        if (sock->rx_sem) {
            xSemaphoreGive(sock->rx_sem);
        }
        // Wait for task to exit
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    if (sock->pcb) {
        udp_recv(sock->pcb, NULL, NULL);
        udp_remove(sock->pcb);
        ESP_LOGI(TAG, "UDP socket closed (port=%u)", sock->local_port);
    }

    if (sock->rx_sem) {
        vSemaphoreDelete(sock->rx_sem);
    }

    free(sock);
}

esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_callback_t callback,
                                         void *user_arg) {
    if (!sock) {
        return ESP_ERR_INVALID_ARG;
    }

    sock->rx_callback = callback;
    sock->rx_callback_arg = user_arg;

    ESP_LOGI(TAG, "RX callback %s", callback ? "registered" : "cleared");
    return ESP_OK;
}

esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len) {
    if (!sock || !sock->pcb || !data || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!sock->ml) {
        return ESP_ERR_INVALID_STATE;
    }

    microlink_t *ml = sock->ml;

    if (len > UDP_MAX_PACKET_SIZE) {
        ESP_LOGE(TAG, "Packet too large: %u", (unsigned int)len);
        return ESP_ERR_INVALID_SIZE;
    }

    char ip_buf[16];

    // Convert destination IP to lwIP format
    ip_addr_t dest_addr;
    microlink_ip_to_lwip(dest_ip, &dest_addr);

    // Allocate pbuf for the data
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (!p) {
        ESP_LOGE(TAG, "Failed to allocate pbuf");
        return ESP_ERR_NO_MEM;
    }

    // Copy data to pbuf
    memcpy(p->payload, data, len);

    // Send via lwIP UDP - routes through WireGuard netif for encryption
    err_t err = udp_sendto(sock->pcb, p, &dest_addr, dest_port);
    pbuf_free(p);

    if (err != ERR_OK) {
        // WireGuard send failed - decode the error
        const char *err_str = "UNKNOWN";
        switch (err) {
            case -1:  err_str = "ERR_MEM (out of memory)"; break;
            case -4:  err_str = "ERR_RTE (no route/peer not found)"; break;
            case -11: err_str = "ERR_CONN (no valid WG session)"; break;
            case -12: err_str = "ERR_IF (netif error)"; break;
            default: break;
        }

        ESP_LOGW(TAG, "udp_sendto(%s:%u) failed: %d (%s)",
                 microlink_vpn_ip_to_str(dest_ip, ip_buf), dest_port, err, err_str);

        // Trigger WireGuard handshake from our side
        // This establishes bidirectional session even without peer initiation
        esp_err_t hs_err = microlink_wireguard_trigger_handshake(ml, dest_ip);
        if (hs_err == ESP_OK) {
            ESP_LOGI(TAG, "WireGuard handshake triggered to %s",
                     microlink_vpn_ip_to_str(dest_ip, ip_buf));
        }

        // Also send CallMeMaybe as backup to request peer initiate handshake
        esp_err_t cmm_err = microlink_disco_send_call_me_maybe(ml, dest_ip);
        if (cmm_err == ESP_OK) {
            ESP_LOGI(TAG, "CallMeMaybe also sent to %s",
                     microlink_vpn_ip_to_str(dest_ip, ip_buf));
        }

        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "UDP sent %u bytes to %s:%u via WireGuard",
             (unsigned int)len, microlink_vpn_ip_to_str(dest_ip, ip_buf), dest_port);

    return ESP_OK;
}

esp_err_t microlink_udp_sendto(microlink_t *ml, uint32_t dest_ip,
                                uint16_t dest_port, const void *data, size_t len) {
    if (!ml || !data || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // Create temporary socket
    microlink_udp_socket_t *sock = microlink_udp_create(ml, 0);
    if (!sock) {
        return ESP_ERR_NO_MEM;
    }

    // Send data
    esp_err_t ret = microlink_udp_send(sock, dest_ip, dest_port, data, len);

    // Close socket
    microlink_udp_close(sock);

    return ret;
}

esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms) {
    if (!sock || !buffer || !len || *len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // Wait for packet with timeout
    uint32_t start_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

    while (1) {
        // Check if packet available in queue
        if (sock->rx_tail != sock->rx_head) {
            udp_rx_packet_t *pkt = &sock->rx_queue[sock->rx_tail];

            if (pkt->valid) {
                size_t copy_len = (pkt->len < *len) ? pkt->len : *len;
                memcpy(buffer, pkt->data, copy_len);
                *len = copy_len;

                if (src_ip) *src_ip = pkt->src_ip;
                if (src_port) *src_port = pkt->src_port;

                pkt->valid = false;
                sock->rx_tail = (sock->rx_tail + 1) % UDP_RX_QUEUE_SIZE;

                return ESP_OK;
            }
        }

        // Check timeout
        uint32_t elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_ms;
        if (timeout_ms > 0 && elapsed >= timeout_ms) {
            return ESP_ERR_TIMEOUT;
        }

        // Process MicroLink state machine while waiting (essential for DERP/WG)
        if (sock->ml) {
            microlink_update(sock->ml);
        }

        // Brief delay
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock) {
    return sock ? sock->local_port : 0;
}

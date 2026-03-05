/**
 * @file microlink.h
 * @brief MicroLink - Tailscale-Compatible VPN for ESP32
 *
 * Production-ready WireGuard/Tailscale implementation optimized for ESP32-S3.
 * Memory footprint: 103KB SRAM + 24KB PSRAM
 *
 * Features:
 * - Full WireGuard encryption (ChaCha20-Poly1305)
 * - Tailscale coordination (ts2021 protocol)
 * - DERP relay support for NAT traversal
 * - STUN client for direct connections
 * - DISCO protocol for path optimization
 *
 * @version 3.0 (Production Ready)
 * @date November 2024
 */

#ifndef MICROLINK_H
#define MICROLINK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration Constants
 * ========================================================================== */

#define MICROLINK_VERSION "3.0.0"

// Memory limits (each peer uses ~200 bytes + endpoints)
#define MICROLINK_MAX_PEERS 16
#define MICROLINK_MAX_ENDPOINTS 8
#define MICROLINK_NETWORK_BUFFER_SIZE 1500

// Timing constants (milliseconds)
#define MICROLINK_HEARTBEAT_INTERVAL_MS 25000  // 25 seconds (required by Tailscale to maintain "online" status)
#define MICROLINK_DISCO_INTERVAL_MS 30000      // 30 seconds
#define MICROLINK_STUN_INTERVAL_MS 300000      // 5 minutes
#define MICROLINK_RECONNECT_DELAY_MS 5000      // 5 seconds

// Tailscale coordination server
#define MICROLINK_CONTROL_SERVER "controlplane.tailscale.com"
#define MICROLINK_CONTROL_PORT 443

// DERP relay servers
// Tailscale DERP regions: 1=NYC, 2=SF, 9=DFW(Dallas), 10=SEA(Seattle), etc.
// Use derp9d.tailscale.com for Dallas region (region ID 9)
// IMPORTANT: DERP hostname number != region ID (derp10 is Seattle/region 10, derp9d is Dallas/region 9)
#define MICROLINK_DERP_SERVER "derp9d.tailscale.com"  // Dallas (dfw) - Region ID 9
#define MICROLINK_DERP_REGION 9  // Must match the server! Region 9 = Dallas
#define MICROLINK_DERP_SERVER_FALLBACK "derp1.tailscale.com"  // NYC fallback (region 1)
#define MICROLINK_DERP_PORT 443

// STUN servers (fallback list)
// NOTE: Tailscale doesn't have a dedicated "stun.tailscale.com" - STUN runs on DERP servers!
// derp1.tailscale.com (NYC) serves STUN on port 3478
#define MICROLINK_STUN_SERVER "derp1.tailscale.com"
#define MICROLINK_STUN_SERVER_FALLBACK "stun.l.google.com"
#define MICROLINK_STUN_PORT 3478
#define MICROLINK_STUN_PORT_GOOGLE 19302

/* ============================================================================
 * Type Definitions
 * ========================================================================== */

/**
 * @brief Connection state
 */
typedef enum {
    MICROLINK_STATE_IDLE = 0,           ///< Not initialized
    MICROLINK_STATE_REGISTERING,        ///< Registering with coordination server
    MICROLINK_STATE_FETCHING_PEERS,     ///< Downloading peer list
    MICROLINK_STATE_CONFIGURING_WG,     ///< Configuring WireGuard
    MICROLINK_STATE_CONNECTED,          ///< Fully connected
    MICROLINK_STATE_MONITORING,         ///< Connected, monitoring paths
    MICROLINK_STATE_ERROR               ///< Error state
} microlink_state_t;

/**
 * @brief Network endpoint (IP:port) - supports both IPv4 and IPv6
 *
 * IPv6 support enables direct connectivity without NAT traversal, which
 * dramatically simplifies connection establishment and reduces latency.
 */
typedef struct {
    union {
        uint32_t ip4;                   ///< IPv4 address (network byte order)
        uint8_t ip6[16];                ///< IPv6 address (network byte order)
    } addr;
    uint16_t port;                      ///< Port (host byte order)
    uint8_t is_ipv6 : 1;                ///< True if IPv6 address
    uint8_t is_derp : 1;                ///< True if DERP relay endpoint
} microlink_endpoint_t;

// Backwards compatibility macro for IPv4-only code
#define MICROLINK_EP_IP4(ep) ((ep)->addr.ip4)

/**
 * @brief Peer device information
 */
typedef struct {
    uint32_t node_id;                   ///< Tailscale node ID
    char hostname[64];                  ///< Device hostname
    uint32_t vpn_ip;                    ///< Tailscale VPN IP (100.x.x.x)
    uint8_t public_key[32];             ///< WireGuard public key
    uint8_t disco_key[32];              ///< DISCO public key (for peer discovery)

    // Endpoints
    microlink_endpoint_t endpoints[MICROLINK_MAX_ENDPOINTS];
    uint8_t endpoint_count;

    // Path metrics
    uint32_t latency_ms;                ///< Current path latency
    uint8_t best_endpoint_idx;          ///< Index of best endpoint
    uint32_t last_seen_ms;              ///< Last received packet time
    bool using_derp;                    ///< True if currently using DERP relay
} microlink_peer_t;

/**
 * @brief Statistics
 */
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t packets_sent;
    uint32_t packets_received;
    uint32_t packets_dropped;
    uint32_t handshakes_completed;
    uint32_t derp_packets_relayed;
    uint32_t direct_packets_sent;
} microlink_stats_t;

/**
 * @brief Configuration structure
 */
typedef struct {
    // Authentication
    const char *auth_key;               ///< Tailscale auth key (required)
    const char *device_name;            ///< Hostname (required)

    // Features
    bool enable_derp;                   ///< Enable DERP relay (recommended)
    bool enable_stun;                   ///< Enable STUN NAT discovery
    bool enable_disco;                  ///< Enable DISCO path optimization

    // Limits
    uint8_t max_peers;                  ///< Max peers (default: 4)
    uint32_t heartbeat_interval_ms;     ///< Heartbeat interval (default: 60000)

    // Callbacks (optional)
    void (*on_connected)(void);         ///< Connected callback
    void (*on_disconnected)(void);      ///< Disconnected callback
    void (*on_peer_added)(const microlink_peer_t *peer);
    void (*on_peer_removed)(uint32_t node_id);
    void (*on_state_change)(microlink_state_t old_state, microlink_state_t new_state);
} microlink_config_t;

/**
 * @brief MicroLink handle (opaque)
 */
typedef struct microlink_context microlink_t;

/* ============================================================================
 * Public API
 * ========================================================================== */

/**
 * @brief Initialize MicroLink with default configuration
 *
 * @param config Configuration structure
 * @return MicroLink handle on success, NULL on failure
 */
microlink_t *microlink_init(const microlink_config_t *config);

/**
 * @brief Deinitialize and free resources
 *
 * @param ml MicroLink handle
 */
void microlink_deinit(microlink_t *ml);

/**
 * @brief Start connection process
 *
 * This is non-blocking. Monitor state with microlink_get_state() or
 * use the on_connected callback.
 *
 * @param ml MicroLink handle
 * @return ESP_OK on success
 */
esp_err_t microlink_connect(microlink_t *ml);

/**
 * @brief Disconnect from Tailscale network
 *
 * @param ml MicroLink handle
 * @return ESP_OK on success
 */
esp_err_t microlink_disconnect(microlink_t *ml);

/**
 * @brief Update state machine (call in main loop)
 *
 * This must be called regularly (every 10-100ms) to process:
 * - Registration
 * - Heartbeats
 * - DISCO probes
 * - Path monitoring
 *
 * @param ml MicroLink handle
 * @return ESP_OK on success
 */
esp_err_t microlink_update(microlink_t *ml);

/**
 * @brief Send packet to peer via VPN
 *
 * @param ml MicroLink handle
 * @param dest_vpn_ip Destination VPN IP (100.x.x.x format, host byte order)
 * @param data Payload data
 * @param len Payload length
 * @return ESP_OK on success
 */
esp_err_t microlink_send(microlink_t *ml, uint32_t dest_vpn_ip,
                         const uint8_t *data, size_t len);

/**
 * @brief Receive packet from peer via VPN
 *
 * This is non-blocking. Returns ESP_ERR_NOT_FOUND if no packet available.
 *
 * @param ml MicroLink handle
 * @param[out] src_vpn_ip Source VPN IP (host byte order)
 * @param[out] buffer Output buffer
 * @param[in,out] len Buffer size on input, actual length on output
 * @return ESP_OK on success, ESP_ERR_NOT_FOUND if no packet
 */
esp_err_t microlink_receive(microlink_t *ml, uint32_t *src_vpn_ip,
                            uint8_t *buffer, size_t *len);

/**
 * @brief Get current connection state
 *
 * @param ml MicroLink handle
 * @return Current state
 */
microlink_state_t microlink_get_state(const microlink_t *ml);

/**
 * @brief Check if connected
 *
 * @param ml MicroLink handle
 * @return true if in CONNECTED or MONITORING state
 */
bool microlink_is_connected(const microlink_t *ml);

/**
 * @brief Get our VPN IP address
 *
 * @param ml MicroLink handle
 * @return VPN IP (100.x.x.x) in host byte order, 0 if not connected
 */
uint32_t microlink_get_vpn_ip(const microlink_t *ml);

/**
 * @brief Get peer list
 *
 * @param ml MicroLink handle
 * @param[out] peers Pointer to peer array (internal storage, do not free)
 * @param[out] count Number of peers
 * @return ESP_OK on success
 */
esp_err_t microlink_get_peers(const microlink_t *ml,
                              const microlink_peer_t **peers,
                              uint8_t *count);

/**
 * @brief Get statistics
 *
 * @param ml MicroLink handle
 * @param[out] stats Statistics structure to fill
 * @return ESP_OK on success
 */
esp_err_t microlink_get_stats(const microlink_t *ml, microlink_stats_t *stats);

/**
 * @brief Get best latency to peer
 *
 * @param ml MicroLink handle
 * @param peer_vpn_ip Peer VPN IP (host byte order)
 * @return Latency in milliseconds, UINT32_MAX if peer not found
 */
uint32_t microlink_get_peer_latency(const microlink_t *ml, uint32_t peer_vpn_ip);

/**
 * @brief Convert VPN IP to string (100.x.x.x format)
 *
 * @param vpn_ip VPN IP (host byte order)
 * @param buffer Output buffer (min 16 bytes)
 * @return Pointer to buffer
 */
const char *microlink_vpn_ip_to_str(uint32_t vpn_ip, char *buffer);

/**
 * @brief Get human-readable state name
 *
 * @param state State enum
 * @return State name string
 */
const char *microlink_state_to_str(microlink_state_t state);

/**
 * @brief Get default configuration
 *
 * Call this first, then modify fields as needed before microlink_init().
 *
 * @param[out] config Configuration structure to fill
 */
void microlink_get_default_config(microlink_config_t *config);

/**
 * @brief Get auto-generated device name from MAC address
 *
 * Returns a unique device name in format "esp32-XXYYZZ" where XXYYZZ
 * is the last 3 bytes of the WiFi MAC address in hex.
 *
 * @return Device name string (static buffer, do not free)
 */
const char *microlink_get_device_name(void);

/* ============================================================================
 * UDP Socket API
 *
 * These functions provide simple UDP send/receive over the Tailscale VPN,
 * equivalent to: echo "data" | nc -u <tailscale_ip> <port>
 *
 * Use these for application-level protocols (like heartbeat messages) that
 * need to communicate with specific IP:port combinations.
 * ========================================================================== */

/**
 * @brief UDP socket handle (opaque)
 */
typedef struct microlink_udp_socket microlink_udp_socket_t;

/**
 * @brief Create a UDP socket bound to the VPN interface
 *
 * Creates a UDP socket that can send/receive data over the Tailscale VPN.
 * The socket is automatically bound to the WireGuard interface.
 *
 * @param ml MicroLink handle (must be connected)
 * @param local_port Local port to bind (0 for auto-assign)
 * @return UDP socket handle on success, NULL on failure
 */
microlink_udp_socket_t *microlink_udp_create(microlink_t *ml, uint16_t local_port);

/**
 * @brief Close and free a UDP socket
 *
 * @param sock UDP socket handle
 */
void microlink_udp_close(microlink_udp_socket_t *sock);

/**
 * @brief Send UDP data to a specific IP:port
 *
 * Equivalent to: echo "data" | nc -u <dest_ip> <dest_port>
 *
 * @param sock UDP socket handle
 * @param dest_ip Destination IP (Tailscale VPN IP, host byte order)
 * @param dest_port Destination port
 * @param data Data to send
 * @param len Data length
 * @return ESP_OK on success, error code on failure
 */
esp_err_t microlink_udp_send(microlink_udp_socket_t *sock, uint32_t dest_ip,
                              uint16_t dest_port, const void *data, size_t len);

/**
 * @brief Send UDP data (convenience function without socket)
 *
 * Creates a temporary socket, sends the data, and closes it.
 * Less efficient for repeated sends - use microlink_udp_create() for that.
 *
 * @param ml MicroLink handle (must be connected)
 * @param dest_ip Destination IP (Tailscale VPN IP, host byte order)
 * @param dest_port Destination port
 * @param data Data to send
 * @param len Data length
 * @return ESP_OK on success, error code on failure
 */
esp_err_t microlink_udp_sendto(microlink_t *ml, uint32_t dest_ip,
                                uint16_t dest_port, const void *data, size_t len);

/**
 * @brief Receive UDP data (non-blocking)
 *
 * @param sock UDP socket handle
 * @param[out] src_ip Source IP (filled on success)
 * @param[out] src_port Source port (filled on success)
 * @param[out] buffer Buffer to receive data
 * @param[in,out] len Buffer size on input, received length on output
 * @param timeout_ms Timeout in milliseconds (0 for non-blocking)
 * @return ESP_OK on success, ESP_ERR_TIMEOUT if no data, error code on failure
 */
esp_err_t microlink_udp_recv(microlink_udp_socket_t *sock, uint32_t *src_ip,
                              uint16_t *src_port, void *buffer, size_t *len,
                              uint32_t timeout_ms);

/**
 * @brief Get the local port of a UDP socket
 *
 * @param sock UDP socket handle
 * @return Local port number, 0 on error
 */
uint16_t microlink_udp_get_local_port(const microlink_udp_socket_t *sock);

/**
 * @brief UDP receive callback type
 *
 * Called when a UDP packet is received on a socket with a registered callback.
 *
 * @param sock UDP socket handle
 * @param src_ip Source IP (host byte order)
 * @param src_port Source port
 * @param data Received data
 * @param len Data length
 * @param user_arg User argument passed to microlink_udp_set_rx_callback
 */
typedef void (*microlink_udp_rx_callback_t)(microlink_udp_socket_t *sock,
                                             uint32_t src_ip, uint16_t src_port,
                                             const uint8_t *data, size_t len,
                                             void *user_arg);

/**
 * @brief Set receive callback for UDP socket
 *
 * When set, the callback is invoked for each received packet instead of
 * queueing for microlink_udp_recv(). This provides lower latency.
 *
 * @param sock UDP socket handle
 * @param callback Callback function (NULL to disable)
 * @param user_arg User argument passed to callback
 * @return ESP_OK on success
 */
esp_err_t microlink_udp_set_rx_callback(microlink_udp_socket_t *sock,
                                         microlink_udp_rx_callback_t callback,
                                         void *user_arg);

/**
 * @brief Get the number of peers
 *
 * @param ml MicroLink handle
 * @return Number of peers in the peer list
 */
int microlink_get_peer_count(const microlink_t *ml);

/**
 * @brief Parse IP string to host byte order uint32
 *
 * Parses "100.64.0.10" to 0x6440000A (host byte order)
 *
 * @param ip_str IP address string (e.g., "100.64.0.10")
 * @return IP in host byte order, 0 on parse error
 */
uint32_t microlink_parse_ip(const char *ip_str);

/* ============================================================================
 * DISCO Functions (for advanced use)
 * ========================================================================== */

/**
 * @brief Send DISCO CallMeMaybe to request peer initiate handshake
 *
 * CallMeMaybe tells the peer "please try to connect to me" and includes
 * our endpoints. This is used to trigger peer-initiated WireGuard handshakes
 * when ESP32-initiated handshakes don't complete due to NAT/firewall asymmetry.
 *
 * @param ml MicroLink handle
 * @param peer_vpn_ip Peer VPN IP (host byte order)
 * @return ESP_OK on success, error code on failure
 */
esp_err_t microlink_disco_send_call_me_maybe(microlink_t *ml, uint32_t peer_vpn_ip);

#ifdef __cplusplus
}
#endif

#endif /* MICROLINK_H */

/**
 * @file microlink_peer_registry.h
 * @brief Flash-based peer registry for 1024+ device support (Task 1.2)
 *
 * Provides persistent storage for up to 1024 Tailscale peers using ESP32's
 * NVS (Non-Volatile Storage). Only active peers are kept in RAM cache.
 */

#ifndef MICROLINK_PEER_REGISTRY_H
#define MICROLINK_PEER_REGISTRY_H

#include "microlink.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration
 * ========================================================================== */

/** Maximum peers stored in flash registry */
#define MICROLINK_PEER_REGISTRY_MAX     1024

/** Active peers kept in RAM cache (for WireGuard) */
#define MICROLINK_PEER_CACHE_SIZE       16

/* ============================================================================
 * API Functions
 * ========================================================================== */

/**
 * @brief Initialize peer registry
 *
 * Opens NVS storage and loads peer count. Must be called before other
 * registry functions.
 *
 * @return ESP_OK on success
 */
esp_err_t microlink_peer_registry_init(void);

/**
 * @brief Deinitialize peer registry
 *
 * Flushes dirty cache entries and closes NVS.
 */
void microlink_peer_registry_deinit(void);

/**
 * @brief Get peer by VPN IP
 *
 * Looks up peer in RAM cache first, then loads from flash if needed.
 * Uses LRU eviction when cache is full.
 *
 * @param vpn_ip Peer's Tailscale VPN IP (100.x.x.x format, host byte order)
 * @return Pointer to peer data, NULL if not found
 *
 * @note Returned pointer is valid until next registry operation that may
 *       cause cache eviction. Copy data if needed for longer.
 */
microlink_peer_t *microlink_peer_registry_get(uint32_t vpn_ip);

/**
 * @brief Add or update peer in registry
 *
 * Stores peer data in flash and updates cache if peer was cached.
 *
 * @param peer Peer data to store
 * @return ESP_OK on success, ESP_ERR_NO_MEM if registry full
 */
esp_err_t microlink_peer_registry_put(const microlink_peer_t *peer);

/**
 * @brief Get total number of registered peers
 *
 * @return Number of peers in flash registry
 */
uint16_t microlink_peer_registry_count(void);

/**
 * @brief Iterate through all registered peers
 *
 * Calls callback for each peer in the registry. Useful for operations
 * that need to process all peers (e.g., finding peer by hostname).
 *
 * @param callback Function called for each peer
 * @param user_data Passed to callback
 * @return Number of peers iterated
 *
 * @note This reads from flash for each peer - use sparingly.
 */
int microlink_peer_registry_foreach(void (*callback)(const microlink_peer_t *peer, void *user_data),
                                     void *user_data);

/**
 * @brief Clear all peers from registry
 *
 * Erases all peer data from flash and clears RAM cache.
 *
 * @return ESP_OK on success
 */
esp_err_t microlink_peer_registry_clear(void);

/**
 * @brief Get active (cached) peers
 *
 * Returns peers currently in RAM cache. These are the peers we're
 * actively communicating with and are configured in WireGuard.
 *
 * @param peers Output array of peer pointers
 * @param max_peers Maximum number of peers to return
 * @return Number of peers returned
 */
int microlink_peer_registry_get_active(microlink_peer_t **peers, int max_peers);

/* ============================================================================
 * Stress Testing (Task 1.2 Verification)
 * ========================================================================== */

/**
 * @brief Stress test result structure
 */
typedef struct {
    uint16_t peers_written;         ///< Number of peers successfully written
    uint16_t peers_read;            ///< Number of peers successfully read back
    uint16_t peers_verified;        ///< Number of peers with matching data
    uint32_t write_time_ms;         ///< Total time to write all peers
    uint32_t read_time_ms;          ///< Total time to read all peers
    uint32_t flash_bytes_used;      ///< Estimated flash bytes used
    bool passed;                    ///< True if all peers verified correctly
} microlink_peer_registry_stress_result_t;

/**
 * @brief Run stress test with synthetic peers
 *
 * Generates and stores `num_peers` synthetic peers with random keys,
 * then reads them back and verifies data integrity.
 *
 * USE FOR TESTING ONLY - will erase existing peer registry!
 *
 * @param num_peers Number of synthetic peers to create (max 1024)
 * @param result Output stress test results
 * @return ESP_OK if test completed (check result->passed for success)
 *
 * @code
 * microlink_peer_registry_stress_result_t result;
 * microlink_peer_registry_stress_test(1024, &result);
 * printf("Wrote %d peers in %lu ms (%.1f KB flash)\n",
 *        result.peers_written, result.write_time_ms,
 *        result.flash_bytes_used / 1024.0f);
 * @endcode
 */
esp_err_t microlink_peer_registry_stress_test(uint16_t num_peers,
                                               microlink_peer_registry_stress_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* MICROLINK_PEER_REGISTRY_H */

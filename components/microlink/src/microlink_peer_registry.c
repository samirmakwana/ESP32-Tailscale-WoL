/**
 * @file microlink_peer_registry.c
 * @brief Flash-based peer registry for 1024+ device support (Task 1.2)
 *
 * Problem: Each peer is ~200 bytes. 1024 peers = 200KB - too much for RAM.
 * Solution: Store peer data in flash (NVS), keep only active peers in RAM cache.
 *
 * Architecture:
 * - Full peer registry stored in NVS (flash) - supports 1024 devices
 * - RAM cache holds only the "active" peers (those we're communicating with)
 * - Cache uses LRU eviction when full
 * - WireGuard only needs active peers anyway (max ~16 simultaneous)
 *
 * Storage Format (NVS):
 * - "peer_count" (uint16): Total number of registered peers
 * - "peer_idx_XXXX" (blob): Peer data for index XXXX (0-1023)
 * - "peer_vpn_XXXXXXXX" (uint16): VPN IP -> peer index mapping
 *
 * This allows:
 * - O(1) lookup by VPN IP
 * - Sequential iteration through all peers
 * - Persistent storage across reboots
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include <string.h>
#include <arpa/inet.h>  // for htonl

static const char *TAG = "ml_peers";

/* ============================================================================
 * Configuration
 * ========================================================================== */

#define PEER_REGISTRY_NVS_PARTITION "peer_nvs"  // Dedicated flash partition (128KB)
#define PEER_REGISTRY_NVS_NAMESPACE "ml_peers"
#define PEER_REGISTRY_MAX_PEERS     1024
#define PEER_CACHE_SIZE             16      // Active peers in RAM

/* ============================================================================
 * Ultra-Compact Peer Storage Format (for flash)
 * ========================================================================== */

/**
 * @brief Ultra-compact peer data for flash storage
 *
 * MEMORY OPTIMIZATION: Reduced from 149 bytes to 84 bytes per peer (44% reduction!)
 *
 * Savings breakdown:
 * - Removed hostname (48 bytes saved) - fetched on-demand from coordination server
 * - Reduced VPN IP to 16-bit suffix (2 bytes saved) - Tailscale IPs are 100.64.x.x
 * - Reduced to 2 endpoints (14 bytes saved) - most peers have 1-2 endpoints
 *
 * Total flash savings for 1024 peers:
 *   Before: 1024 × 149 bytes = 152,576 bytes (~149 KB)
 *   After:  1024 ×  84 bytes =  86,016 bytes (~84 KB)
 *   Saved:  66,560 bytes (~65 KB) - 44% reduction!
 *
 * Tradeoff: Hostname is not stored, only available when peer is in RAM cache
 * (loaded from coordination server). For most applications, only crypto keys matter.
 */
typedef struct __attribute__((packed)) {
    uint32_t node_id;               // 4 bytes - needed for hostname lookup on-demand
    uint16_t vpn_ip_suffix;         // 2 bytes - just x.x from 100.64.x.x (saves 2 bytes)
    uint8_t public_key[32];         // 32 bytes - WireGuard key (cannot compress)
    uint8_t disco_key[32];          // 32 bytes - DISCO key (cannot compress)
    struct {
        uint32_t ip;                // 4 bytes
        uint16_t port;              // 2 bytes
    } __attribute__((packed)) endpoints[2];  // 2 × 6 = 12 bytes (reduced from 4 endpoints)
    uint8_t endpoint_count;         // 1 byte - endpoint count (0-2)
    uint8_t endpoint_flags;         // 1 byte - is_derp flags (bit 0=ep0, bit 1=ep1)
} peer_storage_compact_t;           // Total: 84 bytes

// Verify size at compile time (4+2+32+32+12+1+1 = 84 bytes)
_Static_assert(sizeof(peer_storage_compact_t) == 84, "peer_storage_compact_t size mismatch");

// VPN IP encoding/decoding macros (100.64.x.x -> 16-bit suffix)
#define VPN_IP_TO_SUFFIX(ip) ((uint16_t)(((ip) >> 8) & 0xFF) << 8 | ((ip) & 0xFF))
#define SUFFIX_TO_VPN_IP(suffix) (0x64400000 | (((suffix) >> 8) << 8) | ((suffix) & 0xFF))

/* ============================================================================
 * Peer Cache (RAM)
 * ========================================================================== */

typedef struct {
    microlink_peer_t peer;          // Full peer data
    uint16_t registry_index;        // Index in flash registry
    uint32_t last_access_ms;        // For LRU eviction
    bool valid;                     // Slot in use
    bool dirty;                     // Modified, needs write-back
} peer_cache_entry_t;

typedef struct {
    peer_cache_entry_t entries[PEER_CACHE_SIZE];
    uint16_t total_peers;           // Total in flash registry
    nvs_handle_t nvs_handle;
    bool initialized;
} peer_registry_t;

static peer_registry_t s_registry = {0};

/* ============================================================================
 * Internal Helper Functions
 * ========================================================================== */

/**
 * @brief Convert full peer to ultra-compact storage format
 *
 * NOTE: Hostname is NOT stored to save 48 bytes per peer.
 * Hostname will be "(unknown)" when loaded from flash until
 * coordination server provides it.
 */
static void peer_to_storage(const microlink_peer_t *peer, peer_storage_compact_t *storage) {
    memset(storage, 0, sizeof(peer_storage_compact_t));

    storage->node_id = peer->node_id;

    // Encode VPN IP as 16-bit suffix (100.64.x.x -> just x.x)
    storage->vpn_ip_suffix = VPN_IP_TO_SUFFIX(peer->vpn_ip);

    memcpy(storage->public_key, peer->public_key, 32);
    memcpy(storage->disco_key, peer->disco_key, 32);

    // Copy up to 2 endpoints (most peers have 1-2, prioritize non-DERP)
    uint8_t stored = 0;
    uint8_t flags = 0;

    // First pass: store non-DERP IPv4 endpoints (direct connections preferred)
    // Note: IPv6 endpoints are not stored in compact format (TODO: add IPv6 storage)
    for (int i = 0; i < peer->endpoint_count && stored < 2; i++) {
        if (!peer->endpoints[i].is_derp && !peer->endpoints[i].is_ipv6) {
            storage->endpoints[stored].ip = peer->endpoints[i].addr.ip4;
            storage->endpoints[stored].port = peer->endpoints[i].port;
            // is_derp = false, flag bit stays 0
            stored++;
        }
    }

    // Second pass: fill remaining slots with DERP endpoints
    for (int i = 0; i < peer->endpoint_count && stored < 2; i++) {
        if (peer->endpoints[i].is_derp && !peer->endpoints[i].is_ipv6) {
            storage->endpoints[stored].ip = peer->endpoints[i].addr.ip4;
            storage->endpoints[stored].port = peer->endpoints[i].port;
            flags |= (1 << stored);  // Set is_derp flag for this endpoint
            stored++;
        }
    }

    storage->endpoint_count = stored;
    storage->endpoint_flags = flags;
}

/**
 * @brief Convert ultra-compact storage to full peer format
 *
 * NOTE: Hostname is set to "(node_XXXXXXXX)" placeholder since it's not stored.
 * The coordination server will update it when peer data is refreshed.
 */
static void storage_to_peer(const peer_storage_compact_t *storage, microlink_peer_t *peer) {
    memset(peer, 0, sizeof(microlink_peer_t));

    peer->node_id = storage->node_id;

    // Generate placeholder hostname from node_id (actual hostname not stored)
    snprintf(peer->hostname, sizeof(peer->hostname), "node_%08lx", (unsigned long)storage->node_id);

    // Decode VPN IP from 16-bit suffix back to full IP
    peer->vpn_ip = SUFFIX_TO_VPN_IP(storage->vpn_ip_suffix);

    memcpy(peer->public_key, storage->public_key, 32);
    memcpy(peer->disco_key, storage->disco_key, 32);

    // Restore endpoints (IPv4 only from compact storage)
    peer->endpoint_count = storage->endpoint_count;
    for (int i = 0; i < storage->endpoint_count && i < 2; i++) {
        peer->endpoints[i].addr.ip4 = storage->endpoints[i].ip;
        peer->endpoints[i].port = storage->endpoints[i].port;
        peer->endpoints[i].is_ipv6 = 0;
        peer->endpoints[i].is_derp = (storage->endpoint_flags & (1 << i)) ? 1 : 0;
    }

    // Initialize runtime fields
    peer->latency_ms = UINT32_MAX;
    peer->best_endpoint_idx = 0;
    peer->last_seen_ms = 0;
    peer->using_derp = true;  // Default to DERP until direct path found
}

/**
 * @brief Find LRU cache slot for eviction
 */
static int find_lru_slot(void) {
    int lru_idx = -1;
    uint32_t oldest_time = UINT32_MAX;

    // First, look for empty slot
    for (int i = 0; i < PEER_CACHE_SIZE; i++) {
        if (!s_registry.entries[i].valid) {
            return i;
        }
    }

    // Find oldest (LRU) slot
    for (int i = 0; i < PEER_CACHE_SIZE; i++) {
        if (s_registry.entries[i].last_access_ms < oldest_time) {
            oldest_time = s_registry.entries[i].last_access_ms;
            lru_idx = i;
        }
    }

    return lru_idx;
}

/**
 * @brief Write dirty cache entry back to flash
 */
static esp_err_t flush_cache_entry(int cache_idx) {
    if (!s_registry.entries[cache_idx].valid || !s_registry.entries[cache_idx].dirty) {
        return ESP_OK;
    }

    peer_cache_entry_t *entry = &s_registry.entries[cache_idx];
    peer_storage_compact_t storage;
    peer_to_storage(&entry->peer, &storage);

    char key[16];
    snprintf(key, sizeof(key), "peer_%04d", entry->registry_index);

    esp_err_t err = nvs_set_blob(s_registry.nvs_handle, key, &storage, sizeof(storage));
    if (err == ESP_OK) {
        entry->dirty = false;
        ESP_LOGD(TAG, "Flushed peer %d to flash (70 bytes)", entry->registry_index);
    }

    return err;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/**
 * @brief Initialize peer registry (NVS-backed)
 */
esp_err_t microlink_peer_registry_init(void) {
    if (s_registry.initialized) {
        return ESP_OK;
    }

    // Initialize the dedicated peer_nvs partition first
    esp_err_t err = nvs_flash_init_partition(PEER_REGISTRY_NVS_PARTITION);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // Partition was truncated or format changed, erase and retry
        ESP_LOGW(TAG, "Erasing peer_nvs partition (format change)");
        nvs_flash_erase_partition(PEER_REGISTRY_NVS_PARTITION);
        err = nvs_flash_init_partition(PEER_REGISTRY_NVS_PARTITION);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init peer_nvs partition: %d", err);
        return err;
    }

    // Open namespace within the dedicated partition
    err = nvs_open_from_partition(PEER_REGISTRY_NVS_PARTITION, PEER_REGISTRY_NVS_NAMESPACE,
                                   NVS_READWRITE, &s_registry.nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS namespace: %d", err);
        return err;
    }

    // Read total peer count
    err = nvs_get_u16(s_registry.nvs_handle, "peer_count", &s_registry.total_peers);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        s_registry.total_peers = 0;
        nvs_set_u16(s_registry.nvs_handle, "peer_count", 0);
        nvs_commit(s_registry.nvs_handle);
    }

    // Clear cache
    memset(s_registry.entries, 0, sizeof(s_registry.entries));

    s_registry.initialized = true;
    ESP_LOGI(TAG, "Peer registry initialized: %d peers in flash", s_registry.total_peers);

    return ESP_OK;
}

/**
 * @brief Deinitialize peer registry, flush dirty entries
 */
void microlink_peer_registry_deinit(void) {
    if (!s_registry.initialized) {
        return;
    }

    // Flush all dirty entries
    for (int i = 0; i < PEER_CACHE_SIZE; i++) {
        flush_cache_entry(i);
    }

    nvs_commit(s_registry.nvs_handle);
    nvs_close(s_registry.nvs_handle);
    nvs_flash_deinit_partition(PEER_REGISTRY_NVS_PARTITION);
    s_registry.initialized = false;

    ESP_LOGI(TAG, "Peer registry closed (ultra-compact: 70 bytes/peer)");
}

/**
 * @brief Get peer by VPN IP (loads from flash if not in cache)
 *
 * @param vpn_ip Peer's VPN IP address
 * @return Pointer to peer data (valid until next cache eviction), NULL if not found
 */
microlink_peer_t *microlink_peer_registry_get(uint32_t vpn_ip) {
    if (!s_registry.initialized) {
        return NULL;
    }

    uint32_t now_ms = microlink_get_time_ms();

    // Check cache first
    for (int i = 0; i < PEER_CACHE_SIZE; i++) {
        if (s_registry.entries[i].valid && s_registry.entries[i].peer.vpn_ip == vpn_ip) {
            s_registry.entries[i].last_access_ms = now_ms;
            return &s_registry.entries[i].peer;
        }
    }

    // Not in cache - search flash registry
    // Use VPN IP lookup key for O(1) access
    char vpn_key[20];
    snprintf(vpn_key, sizeof(vpn_key), "vpn_%08lx", (unsigned long)vpn_ip);

    uint16_t peer_idx;
    esp_err_t err = nvs_get_u16(s_registry.nvs_handle, vpn_key, &peer_idx);
    if (err != ESP_OK) {
        return NULL;  // Not found
    }

    // Load peer from flash
    char peer_key[16];
    snprintf(peer_key, sizeof(peer_key), "peer_%04d", peer_idx);

    peer_storage_compact_t storage;
    size_t len = sizeof(storage);
    err = nvs_get_blob(s_registry.nvs_handle, peer_key, &storage, &len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load peer %d from flash", peer_idx);
        return NULL;
    }

    // Find cache slot (may evict LRU entry)
    int slot = find_lru_slot();
    if (slot < 0) {
        ESP_LOGE(TAG, "No cache slot available");
        return NULL;
    }

    // Evict old entry if needed
    if (s_registry.entries[slot].valid) {
        flush_cache_entry(slot);
        ESP_LOGD(TAG, "Evicted peer %d from cache", s_registry.entries[slot].registry_index);
    }

    // Load into cache
    peer_cache_entry_t *entry = &s_registry.entries[slot];
    storage_to_peer(&storage, &entry->peer);
    entry->registry_index = peer_idx;
    entry->last_access_ms = now_ms;
    entry->valid = true;
    entry->dirty = false;

    ESP_LOGD(TAG, "Loaded peer %s (%d) into cache slot %d",
             entry->peer.hostname, peer_idx, slot);

    return &entry->peer;
}

/**
 * @brief Add or update peer in registry
 *
 * @param peer Peer data to store
 * @return ESP_OK on success
 */
esp_err_t microlink_peer_registry_put(const microlink_peer_t *peer) {
    if (!s_registry.initialized || !peer) {
        return ESP_ERR_INVALID_STATE;
    }

    uint32_t now_ms = microlink_get_time_ms();

    // Check if peer already exists (by VPN IP)
    char vpn_key[20];
    snprintf(vpn_key, sizeof(vpn_key), "vpn_%08lx", (unsigned long)peer->vpn_ip);

    uint16_t peer_idx;
    esp_err_t err = nvs_get_u16(s_registry.nvs_handle, vpn_key, &peer_idx);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        // New peer - assign next index
        if (s_registry.total_peers >= PEER_REGISTRY_MAX_PEERS) {
            ESP_LOGE(TAG, "Peer registry full (%d peers)", PEER_REGISTRY_MAX_PEERS);
            return ESP_ERR_NO_MEM;
        }
        peer_idx = s_registry.total_peers;
        s_registry.total_peers++;

        // Save VPN IP -> index mapping
        nvs_set_u16(s_registry.nvs_handle, vpn_key, peer_idx);
        nvs_set_u16(s_registry.nvs_handle, "peer_count", s_registry.total_peers);
    }

    // Store peer data in ultra-compact format (70 bytes)
    peer_storage_compact_t storage;
    peer_to_storage(peer, &storage);

    char peer_key[16];
    snprintf(peer_key, sizeof(peer_key), "peer_%04d", peer_idx);

    err = nvs_set_blob(s_registry.nvs_handle, peer_key, &storage, sizeof(storage));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to store peer %d: %d", peer_idx, err);
        return err;
    }

    nvs_commit(s_registry.nvs_handle);

    // Update cache if peer is cached
    for (int i = 0; i < PEER_CACHE_SIZE; i++) {
        if (s_registry.entries[i].valid && s_registry.entries[i].peer.vpn_ip == peer->vpn_ip) {
            memcpy(&s_registry.entries[i].peer, peer, sizeof(microlink_peer_t));
            s_registry.entries[i].last_access_ms = now_ms;
            s_registry.entries[i].dirty = false;  // Just saved to flash
            break;
        }
    }

    ESP_LOGI(TAG, "Stored peer %s (idx=%d, total=%d)",
             peer->hostname, peer_idx, s_registry.total_peers);

    return ESP_OK;
}

/**
 * @brief Get total number of peers in registry
 */
uint16_t microlink_peer_registry_count(void) {
    return s_registry.initialized ? s_registry.total_peers : 0;
}

/**
 * @brief Iterate through all peers (for bulk operations)
 *
 * @param callback Function called for each peer
 * @param user_data Passed to callback
 * @return Number of peers iterated
 */
int microlink_peer_registry_foreach(void (*callback)(const microlink_peer_t *peer, void *user_data),
                                     void *user_data) {
    if (!s_registry.initialized || !callback) {
        return 0;
    }

    int count = 0;
    peer_storage_compact_t storage;
    microlink_peer_t peer;

    for (uint16_t i = 0; i < s_registry.total_peers; i++) {
        char key[16];
        snprintf(key, sizeof(key), "peer_%04d", i);

        size_t len = sizeof(storage);
        esp_err_t err = nvs_get_blob(s_registry.nvs_handle, key, &storage, &len);
        if (err == ESP_OK) {
            storage_to_peer(&storage, &peer);
            callback(&peer, user_data);
            count++;
        }
    }

    return count;
}

/**
 * @brief Clear all peers from registry
 */
esp_err_t microlink_peer_registry_clear(void) {
    if (!s_registry.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    // Close current handle
    nvs_close(s_registry.nvs_handle);

    // Erase the entire partition (cleanest way to clear all keys)
    esp_err_t err = nvs_flash_erase_partition(PEER_REGISTRY_NVS_PARTITION);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to erase peer_nvs partition: %d", err);
        return err;
    }

    // Reinitialize partition
    err = nvs_flash_init_partition(PEER_REGISTRY_NVS_PARTITION);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to reinit peer_nvs partition: %d", err);
        return err;
    }

    // Reopen namespace
    err = nvs_open_from_partition(PEER_REGISTRY_NVS_PARTITION, PEER_REGISTRY_NVS_NAMESPACE,
                                   NVS_READWRITE, &s_registry.nvs_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to reopen NVS namespace: %d", err);
        return err;
    }

    s_registry.total_peers = 0;
    nvs_set_u16(s_registry.nvs_handle, "peer_count", 0);
    nvs_commit(s_registry.nvs_handle);

    // Clear cache
    memset(s_registry.entries, 0, sizeof(s_registry.entries));

    ESP_LOGI(TAG, "Peer registry cleared");
    return ESP_OK;
}

/**
 * @brief Get cached peers for WireGuard configuration
 *
 * Returns pointers to the active peers currently in the RAM cache.
 * These are the peers we're actually communicating with.
 *
 * @param peers Output array of peer pointers
 * @param max_peers Maximum number of peers to return
 * @return Number of peers returned
 */
int microlink_peer_registry_get_active(microlink_peer_t **peers, int max_peers) {
    if (!s_registry.initialized || !peers) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < PEER_CACHE_SIZE && count < max_peers; i++) {
        if (s_registry.entries[i].valid) {
            peers[count++] = &s_registry.entries[i].peer;
        }
    }

    return count;
}

/* ============================================================================
 * Stress Test Implementation (Task 1.2 Verification)
 * ========================================================================== */

#include "microlink_peer_registry.h"
#include "esp_random.h"

/**
 * @brief Generate a synthetic peer for testing
 *
 * Creates a deterministic peer based on index so we can verify on read-back.
 */
static void generate_synthetic_peer(uint16_t index, microlink_peer_t *peer) {
    memset(peer, 0, sizeof(microlink_peer_t));

    // Deterministic node_id from index
    peer->node_id = 0x10000000 + index;

    // Hostname (will be stripped in compact storage)
    snprintf(peer->hostname, sizeof(peer->hostname), "stress-test-peer-%04d", index);

    // VPN IP: 100.64.x.y where x.y derived from index
    // index 0 -> 100.64.0.1, index 255 -> 100.64.0.255, index 256 -> 100.64.1.0
    peer->vpn_ip = 0x64400001 + index;  // 100.64.0.1 + index

    // Deterministic keys from index (for verification)
    // Public key: SHA-like pattern from index
    for (int i = 0; i < 32; i++) {
        peer->public_key[i] = (uint8_t)((index + i * 7) & 0xFF);
        peer->disco_key[i] = (uint8_t)((index + i * 13) & 0xFF);
    }

    // 1-2 endpoints
    peer->endpoint_count = (index % 2) + 1;

    // Primary endpoint: deterministic IP/port
    peer->endpoints[0].addr.ip4 = htonl(0xC0A80001 + (index % 256));  // 192.168.0.x
    peer->endpoints[0].port = 51820 + (index % 100);
    peer->endpoints[0].is_ipv6 = 0;
    peer->endpoints[0].is_derp = 0;

    // Secondary endpoint (if present): DERP
    if (peer->endpoint_count > 1) {
        peer->endpoints[1].addr.ip4 = htonl(0x0A000001);  // 10.0.0.1 (DERP)
        peer->endpoints[1].port = 443;
        peer->endpoints[1].is_ipv6 = 0;
        peer->endpoints[1].is_derp = 1;
    }
}

/**
 * @brief Verify a peer matches expected synthetic data
 */
static bool verify_synthetic_peer(uint16_t index, const microlink_peer_t *peer) {
    // Verify node_id
    if (peer->node_id != 0x10000000 + index) {
        ESP_LOGE(TAG, "Peer %d: node_id mismatch (expected 0x%08lx, got 0x%08lx)",
                 index, (unsigned long)(0x10000000 + index), (unsigned long)peer->node_id);
        return false;
    }

    // Verify VPN IP
    uint32_t expected_vpn = 0x64400001 + index;
    if (peer->vpn_ip != expected_vpn) {
        ESP_LOGE(TAG, "Peer %d: vpn_ip mismatch (expected 0x%08lx, got 0x%08lx)",
                 index, (unsigned long)expected_vpn, (unsigned long)peer->vpn_ip);
        return false;
    }

    // Verify public key (first few bytes)
    for (int i = 0; i < 8; i++) {
        uint8_t expected = (uint8_t)((index + i * 7) & 0xFF);
        if (peer->public_key[i] != expected) {
            ESP_LOGE(TAG, "Peer %d: public_key[%d] mismatch", index, i);
            return false;
        }
    }

    // Verify disco key (first few bytes)
    for (int i = 0; i < 8; i++) {
        uint8_t expected = (uint8_t)((index + i * 13) & 0xFF);
        if (peer->disco_key[i] != expected) {
            ESP_LOGE(TAG, "Peer %d: disco_key[%d] mismatch", index, i);
            return false;
        }
    }

    return true;
}

/**
 * @brief Run stress test with synthetic peers
 */
esp_err_t microlink_peer_registry_stress_test(uint16_t num_peers,
                                               microlink_peer_registry_stress_result_t *result) {
    if (!result) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(result, 0, sizeof(microlink_peer_registry_stress_result_t));

    if (num_peers > PEER_REGISTRY_MAX_PEERS) {
        num_peers = PEER_REGISTRY_MAX_PEERS;
    }

    ESP_LOGI(TAG, "=== STRESS TEST: %d peers (%d bytes each) ===", num_peers, (int)sizeof(peer_storage_compact_t));
    ESP_LOGI(TAG, "Expected flash usage: %lu bytes (%.1f KB)",
             (unsigned long)(num_peers * sizeof(peer_storage_compact_t)),
             (num_peers * sizeof(peer_storage_compact_t)) / 1024.0f);

    // Initialize registry if needed
    if (!s_registry.initialized) {
        esp_err_t err = microlink_peer_registry_init();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to init registry: %d", err);
            return err;
        }
    }

    // Clear existing data
    ESP_LOGI(TAG, "Clearing existing peer data...");
    microlink_peer_registry_clear();

    // Phase 1: Write all peers
    ESP_LOGI(TAG, "Phase 1: Writing %d peers to flash...", num_peers);
    uint32_t write_start = microlink_get_time_ms();

    microlink_peer_t peer;
    for (uint16_t i = 0; i < num_peers; i++) {
        generate_synthetic_peer(i, &peer);

        esp_err_t err = microlink_peer_registry_put(&peer);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to write peer %d: %d", i, err);
            break;
        }
        result->peers_written++;

        // Progress every 100 peers
        if ((i + 1) % 100 == 0) {
            ESP_LOGI(TAG, "  Written %d/%d peers...", i + 1, num_peers);
        }
    }

    result->write_time_ms = microlink_get_time_ms() - write_start;
    ESP_LOGI(TAG, "Write complete: %d peers in %lu ms (%.1f peers/sec)",
             result->peers_written, (unsigned long)result->write_time_ms,
             result->write_time_ms > 0 ? (result->peers_written * 1000.0f / result->write_time_ms) : 0);

    // Clear cache to force flash reads
    memset(s_registry.entries, 0, sizeof(s_registry.entries));

    // Phase 2: Read back and verify
    ESP_LOGI(TAG, "Phase 2: Reading and verifying %d peers from flash...", num_peers);
    uint32_t read_start = microlink_get_time_ms();

    for (uint16_t i = 0; i < result->peers_written; i++) {
        // Calculate VPN IP for this index
        uint32_t vpn_ip = 0x64400001 + i;

        microlink_peer_t *loaded = microlink_peer_registry_get(vpn_ip);
        if (loaded) {
            result->peers_read++;

            if (verify_synthetic_peer(i, loaded)) {
                result->peers_verified++;
            }
        } else {
            ESP_LOGE(TAG, "Failed to load peer %d (vpn_ip=0x%08lx)", i, (unsigned long)vpn_ip);
        }

        // Progress every 100 peers
        if ((i + 1) % 100 == 0) {
            ESP_LOGI(TAG, "  Verified %d/%d peers...", i + 1, result->peers_written);

            // Clear cache periodically to test LRU eviction
            memset(s_registry.entries, 0, sizeof(s_registry.entries));
        }
    }

    result->read_time_ms = microlink_get_time_ms() - read_start;
    result->flash_bytes_used = result->peers_written * sizeof(peer_storage_compact_t);
    result->passed = (result->peers_verified == result->peers_written);

    ESP_LOGI(TAG, "=== STRESS TEST RESULTS ===");
    ESP_LOGI(TAG, "  Peers written:   %d", result->peers_written);
    ESP_LOGI(TAG, "  Peers read:      %d", result->peers_read);
    ESP_LOGI(TAG, "  Peers verified:  %d", result->peers_verified);
    ESP_LOGI(TAG, "  Write time:      %lu ms", (unsigned long)result->write_time_ms);
    ESP_LOGI(TAG, "  Read time:       %lu ms", (unsigned long)result->read_time_ms);
    ESP_LOGI(TAG, "  Flash used:      %lu bytes (%.1f KB)",
             (unsigned long)result->flash_bytes_used, result->flash_bytes_used / 1024.0f);
    ESP_LOGI(TAG, "  RESULT:          %s", result->passed ? "PASSED" : "FAILED");

    return ESP_OK;
}

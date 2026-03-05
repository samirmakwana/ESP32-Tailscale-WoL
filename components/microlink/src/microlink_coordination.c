/**
 * @file microlink_coordination.c
 * @brief Tailscale coordination client with ts2021 Noise protocol
 *
 * Implements:
 * - Noise_IK handshake (3-message pattern)
 * - HTTP/2 connection to controlplane.tailscale.com
 * - Device registration with auth key
 * - Peer list fetching and parsing
 * - Heartbeat and status updates
 */

#include "microlink_internal.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_heap_caps.h"  // For PSRAM allocation (heap_caps_malloc)
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include "mbedtls/base64.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"  // For mutex synchronization
#include "lwip/sockets.h"  // For raw TCP socket operations (HTTP on port 80)
#include "lwip/netdb.h"    // For getaddrinfo DNS resolution
#include "lwip/inet.h"     // For htonl, ntohl
#include "lwip/tcp.h"      // For TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
#include "esp_netif.h"     // For getting local WiFi IP address
#include "esp_http_client.h"  // For HTTPS /key endpoint fetch
#include "esp_crt_bundle.h"   // For TLS certificate bundle
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>        // For close()
#include <fcntl.h>         // For fcntl, O_NONBLOCK
#include <sys/time.h>      // For struct timeval

// Crypto primitives from wireguard-lwip
#include "x25519.h"
#include "chacha20poly1305.h"
#include "blake2s.h"
#include "nacl_box.h"  // For NodeKeyChallengeResponse (NaCl crypto_box)

static const char *TAG = "ml_coord";

// Track skipped server frames for nonce adjustment
static int g_skipped_server_frames = 0;

// Store server's proactive frames to decrypt after handshake
static uint8_t *g_server_extra_data = NULL;
static int g_server_extra_data_len = 0;

// Store the nodeKeyChallenge from EarlyNoise for MapRequest
static uint8_t g_node_key_challenge[32] = {0};
static bool g_has_node_key_challenge = false;

// Tailscale control plane (configurable for Headscale/Ionscale via Kconfig)
#ifdef CONFIG_MICROLINK_CUSTOM_COORD_SERVER
#define TAILSCALE_CONTROL_HOST CONFIG_MICROLINK_COORD_HOST
#define TAILSCALE_CONTROL_PORT CONFIG_MICROLINK_COORD_PORT
#else
#define TAILSCALE_CONTROL_HOST "controlplane.tailscale.com"
#define TAILSCALE_CONTROL_PORT 443
#endif
#define TAILSCALE_TS2021_PATH  "/ts2021"
#define TAILSCALE_PROTOCOL_VERSION 131  // Tailscale Control Protocol version (CapabilityVersion)

// Noise protocol constants
#define NOISE_PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_BLAKE2s"
#define NOISE_HASH_LEN      32
#define NOISE_KEY_LEN       32
#define NOISE_MAC_LEN       16
#define NOISE_NONCE_LEN     12

/* ============================================================================
 * Noise Protocol State
 * ========================================================================== */

typedef struct {
    // Handshake state
    uint8_t h[NOISE_HASH_LEN];           // Handshake hash
    uint8_t ck[NOISE_HASH_LEN];          // Chaining key

    // Local keypairs
    uint8_t local_static_private[32];    // s (machine key)
    uint8_t local_static_public[32];     // s.pub
    uint8_t local_ephemeral_private[32]; // e
    uint8_t local_ephemeral_public[32];  // e.pub

    // Remote public key
    uint8_t remote_static_public[32];    // rs (server's public key)

    // Transport keys (derived after handshake)
    uint8_t tx_key[NOISE_KEY_LEN];       // Client -> Server encryption key
    uint8_t rx_key[NOISE_KEY_LEN];       // Server -> Client decryption key
    uint64_t tx_nonce;                   // Transmission nonce counter
    uint64_t rx_nonce;                   // Reception nonce counter

    bool handshake_complete;
} noise_state_t;

/* ============================================================================
 * Noise Protocol Helper Functions
 * ========================================================================== */

/**
 * @brief Log hex bytes for debugging crypto operations
 * NOTE: Using %u instead of %zu because nano printf doesn't support %zu
 */
static void log_hex(const char *label, const uint8_t *data, size_t len) {
    if (!data || !label || len == 0) {
        ESP_LOGW(TAG, "log_hex: invalid params (label=%p, data=%p, len=%u)",
                 (void *)label, (void *)data, (unsigned int)len);
        return;
    }
    char hex[128];
    size_t hex_len = (len > 32) ? 32 : len;  // Show first 32 bytes max
    for (size_t i = 0; i < hex_len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[hex_len * 2] = '\0';
    if (len > 32) {
        ESP_LOGI(TAG, "%s (%u bytes): %s...", label, (unsigned int)len, hex);
    } else {
        ESP_LOGI(TAG, "%s (%u bytes): %s", label, (unsigned int)len, hex);
    }
}

/**
 * @brief BLAKE2s-256 hash
 */
static void noise_hash(uint8_t *out, const uint8_t *data, size_t len) {
    blake2s_ctx state;
    blake2s_init(&state, NOISE_HASH_LEN, NULL, 0);
    blake2s_update(&state, data, len);
    blake2s_final(&state, out);
}

/**
 * @brief HMAC-BLAKE2s (proper HMAC construction, NOT BLAKE2s keyed mode)
 *
 * Noise protocol requires standard HMAC construction even for BLAKE2s:
 * "HMAC is used with all hash functions instead of allowing hashes to use
 *  a more specialized function (e.g. keyed BLAKE2)" - Noise spec section 15.2
 *
 * HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 * where K' = H(K) if len(K) > blocklen, else K padded with zeros to blocklen
 * BLAKE2s blocklen = 64, ipad = 0x36 repeated, opad = 0x5c repeated
 */
#define BLAKE2S_BLOCKLEN 64

static void noise_hmac(uint8_t *out, const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len) {
    uint8_t k_prime[BLAKE2S_BLOCKLEN];
    uint8_t inner_pad[BLAKE2S_BLOCKLEN];
    uint8_t outer_pad[BLAKE2S_BLOCKLEN];
    uint8_t inner_hash[NOISE_HASH_LEN];
    blake2s_ctx state;

    // Step 1: Derive K' (key padded/hashed to block length)
    memset(k_prime, 0, BLAKE2S_BLOCKLEN);
    if (key_len > BLAKE2S_BLOCKLEN) {
        // K' = H(K) if key is longer than block size
        noise_hash(k_prime, key, key_len);
    } else {
        // K' = K padded with zeros
        memcpy(k_prime, key, key_len);
    }

    // Step 2: Compute inner and outer pads
    for (int i = 0; i < BLAKE2S_BLOCKLEN; i++) {
        inner_pad[i] = k_prime[i] ^ 0x36;
        outer_pad[i] = k_prime[i] ^ 0x5c;
    }

    // Step 3: Inner hash = H(inner_pad || data)
    blake2s_init(&state, NOISE_HASH_LEN, NULL, 0);
    blake2s_update(&state, inner_pad, BLAKE2S_BLOCKLEN);
    blake2s_update(&state, data, data_len);
    blake2s_final(&state, inner_hash);

    // Step 4: Outer hash = H(outer_pad || inner_hash)
    blake2s_init(&state, NOISE_HASH_LEN, NULL, 0);
    blake2s_update(&state, outer_pad, BLAKE2S_BLOCKLEN);
    blake2s_update(&state, inner_hash, NOISE_HASH_LEN);
    blake2s_final(&state, out);
}

/**
 * @brief HKDF key derivation with BLAKE2s
 *
 * Derives up to 3 output keys from input key material using HKDF-BLAKE2s.
 * Pass NULL for unused outputs.
 */
static void noise_hkdf(uint8_t *out1, uint8_t *out2, uint8_t *out3,
                       const uint8_t *chaining_key,
                       const uint8_t *input_key_material, size_t ikm_len) {
    uint8_t temp_key[NOISE_HASH_LEN];
    uint8_t hmac_out[NOISE_HASH_LEN];

    // temp_key = HMAC-BLAKE2s(chaining_key, input_key_material)
    noise_hmac(temp_key, chaining_key, NOISE_HASH_LEN,
               input_key_material, ikm_len);

    // output1 = HMAC-BLAKE2s(temp_key, 0x01)
    if (out1) {
        uint8_t one = 0x01;
        noise_hmac(hmac_out, temp_key, NOISE_HASH_LEN, &one, 1);
        memcpy(out1, hmac_out, NOISE_HASH_LEN);
    }

    // output2 = HMAC-BLAKE2s(temp_key, output1 || 0x02)
    if (out2) {
        uint8_t input[NOISE_HASH_LEN + 1];
        memcpy(input, hmac_out, NOISE_HASH_LEN);
        input[NOISE_HASH_LEN] = 0x02;
        noise_hmac(hmac_out, temp_key, NOISE_HASH_LEN, input, NOISE_HASH_LEN + 1);
        memcpy(out2, hmac_out, NOISE_HASH_LEN);
    }

    // output3 = HMAC-BLAKE2s(temp_key, output2 || 0x03)
    if (out3) {
        uint8_t input[NOISE_HASH_LEN + 1];
        memcpy(input, hmac_out, NOISE_HASH_LEN);
        input[NOISE_HASH_LEN] = 0x03;
        noise_hmac(hmac_out, temp_key, NOISE_HASH_LEN, input, NOISE_HASH_LEN + 1);
        memcpy(out3, hmac_out, NOISE_HASH_LEN);
    }
}

/**
 * @brief Update handshake hash: h = BLAKE2s(h || data)
 */
static void noise_mix_hash(noise_state_t *noise, const uint8_t *data, size_t len) {
    // Allocate combined buffer dynamically to avoid stack overflow
    size_t combined_len = NOISE_HASH_LEN + len;
    uint8_t *combined = malloc(combined_len);
    if (!combined) {
        ESP_LOGE(TAG, "Failed to allocate buffer for noise_mix_hash");
        return;
    }

    memcpy(combined, noise->h, NOISE_HASH_LEN);
    memcpy(combined + NOISE_HASH_LEN, data, len);
    noise_hash(noise->h, combined, combined_len);

    free(combined);
}

/**
 * @brief Update chaining key and derive new encryption key
 *
 * ck, k = HKDF(ck, input_key_material)
 */
static void noise_mix_key(noise_state_t *noise, const uint8_t *ikm, size_t ikm_len,
                          uint8_t *k_out) {
    uint8_t new_ck[NOISE_HASH_LEN];
    noise_hkdf(new_ck, k_out, NULL, noise->ck, ikm, ikm_len);
    memcpy(noise->ck, new_ck, NOISE_HASH_LEN);
}

/**
 * @brief Convert nonce to Tailscale format (big-endian in the 64-bit counter portion)
 *
 * Tailscale uses: 4 bytes zeros + 8 bytes BIG-ENDIAN counter
 * Our chacha20poly1305 library uses: 4 bytes zeros + 8 bytes LITTLE-ENDIAN counter
 *
 * So we need to byte-swap the nonce value before passing to the library.
 */
static uint64_t nonce_to_tailscale_format(uint64_t nonce) {
    // Byte-swap the 64-bit nonce value
    // This converts from native (little-endian on ESP32) to big-endian byte order
    // which the chacha20 library will then interpret as little-endian, giving us
    // the desired big-endian byte representation in the nonce field.
    return __builtin_bswap64(nonce);
}

static esp_err_t noise_encrypt(const uint8_t *key, uint64_t nonce,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext) {
    // Convert nonce to Tailscale's big-endian format
    uint64_t ts_nonce = nonce_to_tailscale_format(nonce);

    // Encrypt: ciphertext || tag
    chacha20poly1305_encrypt(ciphertext, plaintext, plaintext_len,
                            ad, ad_len, ts_nonce, key);

    return ESP_OK;
}

/**
 * @brief Decrypt ciphertext with ChaCha20-Poly1305
 *
 * @param key 32-byte decryption key
 * @param nonce 8-byte nonce
 * @param ad Associated data
 * @param ad_len Associated data length
 * @param ciphertext Ciphertext + 16-byte MAC
 * @param ciphertext_len Ciphertext length (includes MAC)
 * @param plaintext Output buffer
 * @return ESP_OK on success, ESP_ERR_INVALID_MAC if authentication fails
 */
static esp_err_t noise_decrypt(const uint8_t *key, uint64_t nonce,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *plaintext) {
    // Convert nonce to Tailscale's big-endian format
    uint64_t ts_nonce = nonce_to_tailscale_format(nonce);

    // NOTE: chacha20poly1305_decrypt expects ciphertext_len to INCLUDE the MAC
    // It will subtract POLY1305_MAC_SIZE (16) internally to get plaintext length
    if (!chacha20poly1305_decrypt(plaintext, ciphertext, ciphertext_len,
                                  ad, ad_len, ts_nonce, key)) {
        return ESP_ERR_INVALID_MAC;
    }

    return ESP_OK;
}

/* ============================================================================
 * Noise_IK Handshake Implementation
 * ========================================================================== */

/**
 * @brief Initialize Noise_IK handshake state with Tailscale prologue
 *
 * @param noise Noise state structure
 * @param local_static_private 32-byte machine private key (NULL to generate)
 * @param remote_static_public 32-byte server public key
 * @param protocol_version Tailscale protocol version (e.g., 41)
 */
static void noise_init(noise_state_t *noise,
                       const uint8_t *local_static_private,
                       const uint8_t *remote_static_public,
                       uint16_t protocol_version) {
    memset(noise, 0, sizeof(noise_state_t));

    ESP_LOGI(TAG, "=== Noise State Initialization ===");

    // Initialize handshake hash with protocol name
    ESP_LOGI(TAG, "Protocol name: %s", NOISE_PROTOCOL_NAME);
    noise_hash(noise->h, (const uint8_t *)NOISE_PROTOCOL_NAME,
               strlen(NOISE_PROTOCOL_NAME));
    log_hex("h after hash(protocol)", noise->h, 32);

    // Initialize chaining key with protocol name hash
    memcpy(noise->ck, noise->h, NOISE_HASH_LEN);
    log_hex("ck = h", noise->ck, 32);

    // Mix in Tailscale prologue: "Tailscale Control Protocol v<version>"
    // The version number comes from the protocol_version parameter (e.g., 131)
    // This is dynamically constructed to match the version in the message header.
    // Server uses: protocolVersionPrologue(clientVersion) which builds "Tailscale Control Protocol v" + version
    char prologue[64];
    int prologue_len = snprintf(prologue, sizeof(prologue),
                                "Tailscale Control Protocol v%u", protocol_version);
    noise_mix_hash(noise, (const uint8_t *)prologue, prologue_len);

    ESP_LOGI(TAG, "Noise prologue: \"%s\" (%d bytes)", prologue, prologue_len);
    log_hex("h after MixHash(prologue)", noise->h, 32);

    // Set remote static public key
    memcpy(noise->remote_static_public, remote_static_public, 32);
    noise_mix_hash(noise, remote_static_public, 32);
    log_hex("h after MixHash(rs)", noise->h, 32);

    // Generate or set local static keypair
    if (local_static_private) {
        memcpy(noise->local_static_private, local_static_private, 32);
        x25519_base(noise->local_static_public, noise->local_static_private, 1);
        ESP_LOGI(TAG, "Using provided machine key");
    } else {
        // Generate new machine key
        esp_fill_random(noise->local_static_private, 32);
        x25519_base(noise->local_static_public, noise->local_static_private, 1);
        ESP_LOGI(TAG, "Generated new machine key");
    }
    log_hex("Local static public key (s)", noise->local_static_public, 32);

    // Generate ephemeral keypair for this session
    esp_fill_random(noise->local_ephemeral_private, 32);
    x25519_base(noise->local_ephemeral_public, noise->local_ephemeral_private, 1);
    log_hex("Local ephemeral public key (e)", noise->local_ephemeral_public, 32);

    ESP_LOGI(TAG, "=== Noise Init Complete ===");
}

/**
 * @brief Generate Noise_IK handshake message 1 (initiator -> responder)
 *
 * Tailscale's complete message 1 structure (101 bytes total):
 *   Header (5 bytes):
 *     - 2 bytes: protocol version (uint16, big-endian)
 *     - 1 byte: message type (0x01)
 *     - 2 bytes: payload length = 96 (uint16, big-endian)
 *   Payload (96 bytes):
 *     - 32 bytes: ephemeral public key (e)
 *     - 48 bytes: encrypted static public key (s + MAC)
 *     - 16 bytes: final authentication tag (empty encryption)
 *
 * Noise operations:
 *   -> e, es, s, ss
 *
 * NOTE: Tailscale does NOT include application payload in message 1.
 *       The registration JSON is sent AFTER handshake completion.
 *
 * @param noise Initialized noise state
 * @param protocol_version Tailscale protocol version (e.g., 131)
 * @param out Output buffer (must be >= 101 bytes)
 * @return Message length (always 101 bytes)
 */
static size_t noise_write_message_1(noise_state_t *noise, uint16_t protocol_version, uint8_t *out) {
    size_t offset = 0;
    uint8_t dh_result[32];
    uint8_t k[NOISE_KEY_LEN];

    ESP_LOGI(TAG, "=== Noise Message 1 Generation (detailed) ===");

    // Log initial state
    log_hex("Initial h (hash)", noise->h, 32);
    log_hex("Initial ck (chaining key)", noise->ck, 32);
    log_hex("Server public key (rs)", noise->remote_static_public, 32);
    log_hex("Local static public (s)", noise->local_static_public, 32);
    log_hex("Local ephemeral public (e)", noise->local_ephemeral_public, 32);

    // Write 5-byte Tailscale message header
    out[offset++] = (protocol_version >> 8) & 0xFF;  // Version high byte
    out[offset++] = protocol_version & 0xFF;         // Version low byte
    out[offset++] = 0x01;                            // Message type: Initiation
    out[offset++] = 0x00;                            // Payload length high byte (96 = 0x0060)
    out[offset++] = 0x60;                            // Payload length low byte

    ESP_LOGI(TAG, "Header: version=%u, type=0x01, len=96", protocol_version);

    // 1. Write ephemeral public key (e)
    memcpy(out + offset, noise->local_ephemeral_public, 32);
    noise_mix_hash(noise, noise->local_ephemeral_public, 32);
    offset += 32;

    log_hex("After MixHash(e), h", noise->h, 32);

    // 2. Perform DH(e, rs) -> es
    x25519(dh_result, noise->local_ephemeral_private, noise->remote_static_public, 1);
    log_hex("DH(e, rs) = es", dh_result, 32);

    noise_mix_key(noise, dh_result, 32, k);
    log_hex("After MixKey(es), ck", noise->ck, 32);
    log_hex("Derived key k", k, 32);

    // 3. Encrypt and write static public key (s)
    noise_encrypt(k, 0, noise->h, NOISE_HASH_LEN,
                 noise->local_static_public, 32,
                 out + offset);
    log_hex("Encrypted s (48 bytes)", out + offset, 48);

    noise_mix_hash(noise, out + offset, 32 + NOISE_MAC_LEN);
    offset += 32 + NOISE_MAC_LEN;  // 48 bytes total

    log_hex("After MixHash(enc_s), h", noise->h, 32);

    // 4. Perform DH(s, rs) -> ss
    x25519(dh_result, noise->local_static_private, noise->remote_static_public, 1);
    log_hex("DH(s, rs) = ss", dh_result, 32);

    noise_mix_key(noise, dh_result, 32, k);
    log_hex("After MixKey(ss), ck", noise->ck, 32);
    log_hex("Final key k for auth tag", k, 32);

    // 5. Encrypt empty data to generate final authentication tag
    // This binds the handshake hash and proves knowledge of both DH secrets
    uint8_t empty[1] = {0};  // Dummy buffer (won't be used, but avoids NULL pointer)
    noise_encrypt(k, 0, noise->h, NOISE_HASH_LEN,
                 empty, 0,  // Empty plaintext (0 bytes, but valid pointer)
                 out + offset);
    log_hex("Final auth tag (16 bytes)", out + offset, 16);

    noise_mix_hash(noise, out + offset, NOISE_MAC_LEN);
    offset += NOISE_MAC_LEN;  // 16 bytes

    log_hex("Final h", noise->h, 32);
    log_hex("Final message 1", out, offset);

    ESP_LOGI(TAG, "=== Message 1 complete: %u bytes ===", (unsigned int)offset);

    return offset;  // Should be 101 bytes (5-byte header + 96-byte payload)
}

/**
 * @brief Parse Noise_IK handshake message 2 (responder -> initiator)
 *
 * Message structure:
 *   - 32 bytes: server ephemeral public key (e)
 *   - N+16 bytes: encrypted response payload (node info + MAC)
 *
 * Noise operations:
 *   <- e, ee, se, payload
 *
 * Derives transport keys: tx_key (client->server), rx_key (server->client)
 *
 * @param noise Noise state (after message 1)
 * @param msg Message 2 from server
 * @param msg_len Message length
 * @param payload_out Decrypted payload buffer
 * @param payload_len_out Decrypted payload length (output)
 * @return ESP_OK on success
 */
static esp_err_t noise_read_message_2(noise_state_t *noise,
                                      const uint8_t *msg, size_t msg_len,
                                      uint8_t *payload_out, size_t *payload_len_out) {
    if (msg_len < 32 + NOISE_MAC_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t offset = 0;
    uint8_t remote_ephemeral[32];
    uint8_t dh_result[32];
    uint8_t k[NOISE_KEY_LEN];

    ESP_LOGI(TAG, "=== Noise Message 2 Processing ===");
    log_hex("Input message", msg, msg_len);
    log_hex("h before processing", noise->h, 32);
    log_hex("ck before processing", noise->ck, 32);

    // 1. Read server ephemeral public key (e)
    memcpy(remote_ephemeral, msg + offset, 32);
    log_hex("Server ephemeral (re)", remote_ephemeral, 32);
    noise_mix_hash(noise, remote_ephemeral, 32);
    log_hex("h after MixHash(re)", noise->h, 32);
    offset += 32;

    // 2. Perform DH(e, re) -> ee (our ephemeral with their ephemeral)
    x25519(dh_result, noise->local_ephemeral_private, remote_ephemeral, 1);
    log_hex("DH(e, re) = ee", dh_result, 32);
    noise_mix_key(noise, dh_result, 32, k);
    log_hex("ck after MixKey(ee)", noise->ck, 32);
    log_hex("k after MixKey(ee)", k, 32);

    // 3. Perform DH(s, re) -> se (our static with their ephemeral)
    x25519(dh_result, noise->local_static_private, remote_ephemeral, 1);
    log_hex("DH(s, re) = se", dh_result, 32);
    noise_mix_key(noise, dh_result, 32, k);
    log_hex("ck after MixKey(se)", noise->ck, 32);
    log_hex("k after MixKey(se) - decryption key", k, 32);

    // 4. Decrypt payload using k from last MixKey
    // The payload should be empty for IK pattern (just 16-byte MAC)
    size_t payload_ciphertext_len = msg_len - offset;
    ESP_LOGI(TAG, "Payload ciphertext length: %u bytes (should be 16 for empty payload)", (unsigned int)payload_ciphertext_len);
    log_hex("Ciphertext to decrypt", msg + offset, payload_ciphertext_len);
    log_hex("AD (h) for decryption", noise->h, NOISE_HASH_LEN);

    esp_err_t ret = noise_decrypt(k, 0, noise->h, NOISE_HASH_LEN,
                                  msg + offset, payload_ciphertext_len,
                                  payload_out);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to decrypt message 2 payload (MAC verification failed)");
        return ret;
    }

    *payload_len_out = payload_ciphertext_len - NOISE_MAC_LEN;
    ESP_LOGI(TAG, "Decrypted payload length: %u bytes", (unsigned int)*payload_len_out);

    // MixHash the ciphertext (including MAC)
    noise_mix_hash(noise, msg + offset, payload_ciphertext_len);
    log_hex("h after MixHash(ciphertext)", noise->h, 32);

    // 5. NOW derive transport keys (Split operation)
    // This happens AFTER successful decryption
    uint8_t temp1[NOISE_HASH_LEN], temp2[NOISE_HASH_LEN];
    noise_hkdf(temp1, temp2, NULL, noise->ck, NULL, 0);
    memcpy(noise->tx_key, temp1, NOISE_KEY_LEN);
    memcpy(noise->rx_key, temp2, NOISE_KEY_LEN);
    noise->tx_nonce = 0;
    noise->rx_nonce = 0;

    log_hex("tx_key (initiator->responder)", noise->tx_key, 32);
    log_hex("rx_key (responder->initiator)", noise->rx_key, 32);

    noise->handshake_complete = true;
    ESP_LOGI(TAG, "=== Noise Message 2 Complete ===");

    return ESP_OK;
}

/* ============================================================================
 * Server Public Key (fetched dynamically or fallback to Tailscale default)
 * ========================================================================== */

// Fallback: Tailscale coordination server public key (Curve25519)
// Source: controlplane.tailscale.com/key?v=131
// IMPORTANT: This is the "publicKey" (ts2021/Noise), NOT the "legacyPublicKey" (nacl crypto_box)
// Key: mkey:7d2792f9c98d753d2042471536801949104c247f95eac770f8fb321595e2173b
static const uint8_t TAILSCALE_SERVER_PUBLIC_KEY_DEFAULT[32] = {
    0x7d, 0x27, 0x92, 0xf9, 0xc9, 0x8d, 0x75, 0x3d,
    0x20, 0x42, 0x47, 0x15, 0x36, 0x80, 0x19, 0x49,
    0x10, 0x4c, 0x24, 0x7f, 0x95, 0xea, 0xc7, 0x70,
    0xf8, 0xfb, 0x32, 0x15, 0x95, 0xe2, 0x17, 0x3b
};

// Dynamic server public key (fetched from /key endpoint)
static uint8_t g_server_public_key[32];
static bool g_server_public_key_fetched = false;

/**
 * @brief Convert hex character to nibble value
 */
static int hex_char_to_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Fetch server's Noise public key from /key endpoint via HTTPS
 *
 * This enables automatic support for Headscale/Ionscale without manual key configuration.
 * The endpoint returns JSON: {"publicKey":"mkey:hex...","legacyPublicKey":"nodekey:hex..."}
 *
 * @param out_key Output buffer for 32-byte public key
 * @return ESP_OK on success, error code on failure
 */
static esp_err_t fetch_server_public_key(uint8_t *out_key) {
    ESP_LOGI(TAG, "Fetching server public key from https://%s:%d/key?v=%d",
             TAILSCALE_CONTROL_HOST, TAILSCALE_CONTROL_PORT, TAILSCALE_PROTOCOL_VERSION);

    esp_err_t ret = ESP_FAIL;
    char *response_buf = NULL;
    esp_http_client_handle_t client = NULL;

    // Allocate response buffer
    response_buf = malloc(1024);
    if (!response_buf) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        return ESP_ERR_NO_MEM;
    }

    // Build URL
    char url[256];
    snprintf(url, sizeof(url), "https://%s:%d/key?v=%d",
             TAILSCALE_CONTROL_HOST, TAILSCALE_CONTROL_PORT, TAILSCALE_PROTOCOL_VERSION);

    // Configure HTTP client
    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,  // Use certificate bundle for TLS
    };

    client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    // Perform request
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        ret = err;
        goto cleanup;
    }

    int content_length = esp_http_client_fetch_headers(client);
    if (content_length < 0) {
        ESP_LOGE(TAG, "Failed to fetch headers");
        ret = ESP_FAIL;
        goto cleanup;
    }

    int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        ESP_LOGE(TAG, "Server returned status %d", status);
        ret = ESP_FAIL;
        goto cleanup;
    }

    // Read response
    int read_len = esp_http_client_read(client, response_buf, 1023);
    if (read_len <= 0) {
        ESP_LOGE(TAG, "Failed to read response");
        ret = ESP_FAIL;
        goto cleanup;
    }
    response_buf[read_len] = '\0';

    ESP_LOGD(TAG, "Key response: %s", response_buf);

    // Parse JSON to extract publicKey
    // Format: {"publicKey":"mkey:7d2792f9c98d753d...","legacyPublicKey":"..."}
    cJSON *root = cJSON_Parse(response_buf);
    if (!root) {
        ESP_LOGE(TAG, "Failed to parse JSON response");
        ret = ESP_FAIL;
        goto cleanup;
    }

    cJSON *pub_key_json = cJSON_GetObjectItem(root, "publicKey");
    if (!pub_key_json || !cJSON_IsString(pub_key_json)) {
        ESP_LOGE(TAG, "publicKey not found in response");
        cJSON_Delete(root);
        ret = ESP_FAIL;
        goto cleanup;
    }

    const char *pub_key_str = pub_key_json->valuestring;

    // Expect format "mkey:hex_string" (64 hex chars = 32 bytes)
    if (strncmp(pub_key_str, "mkey:", 5) != 0) {
        ESP_LOGE(TAG, "Invalid publicKey format (expected mkey:...)");
        cJSON_Delete(root);
        ret = ESP_FAIL;
        goto cleanup;
    }

    const char *hex_str = pub_key_str + 5;  // Skip "mkey:"
    size_t hex_len = strlen(hex_str);
    if (hex_len != 64) {
        ESP_LOGE(TAG, "Invalid publicKey length: %d (expected 64)", (int)hex_len);
        cJSON_Delete(root);
        ret = ESP_FAIL;
        goto cleanup;
    }

    // Decode hex to bytes
    for (int i = 0; i < 32; i++) {
        int hi = hex_char_to_nibble(hex_str[i * 2]);
        int lo = hex_char_to_nibble(hex_str[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            ESP_LOGE(TAG, "Invalid hex character in publicKey");
            cJSON_Delete(root);
            ret = ESP_FAIL;
            goto cleanup;
        }
        out_key[i] = (hi << 4) | lo;
    }

    cJSON_Delete(root);
    log_hex("Fetched server public key", out_key, 32);
    ret = ESP_OK;

cleanup:
    if (client) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
    }
    if (response_buf) {
        free(response_buf);
    }
    return ret;
}

/**
 * @brief Get server public key (fetch if needed, fallback to default for Tailscale)
 */
static const uint8_t *get_server_public_key(void) {
    // If already fetched, return cached key
    if (g_server_public_key_fetched) {
        return g_server_public_key;
    }

    // Try to fetch from /key endpoint
    esp_err_t err = fetch_server_public_key(g_server_public_key);
    if (err == ESP_OK) {
        g_server_public_key_fetched = true;
        ESP_LOGI(TAG, "Using dynamically fetched server public key");
        return g_server_public_key;
    }

    // Fallback to hardcoded Tailscale key
    ESP_LOGW(TAG, "Failed to fetch server key, using default Tailscale key");
    memcpy(g_server_public_key, TAILSCALE_SERVER_PUBLIC_KEY_DEFAULT, 32);
    g_server_public_key_fetched = true;
    return g_server_public_key;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

/* NVS keys for machine key persistence */
#define NVS_NAMESPACE       "microlink"
#define NVS_KEY_MACHINE_PRI "machine_pri"
#define NVS_KEY_MACHINE_PUB "machine_pub"

/**
 * @brief Load machine key from NVS, or generate new one if not found
 */
static esp_err_t load_or_generate_machine_key(microlink_t *ml) {
    nvs_handle_t nvs;
    esp_err_t ret;
    bool need_save = false;

    // Open NVS namespace
    ret = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS, will generate ephemeral key: %d", ret);
        goto generate_new;
    }

    // Try to load private key
    size_t key_len = 32;
    ret = nvs_get_blob(nvs, NVS_KEY_MACHINE_PRI, ml->coordination.machine_private_key, &key_len);
    if (ret == ESP_OK && key_len == 32) {
        // Load public key
        key_len = 32;
        ret = nvs_get_blob(nvs, NVS_KEY_MACHINE_PUB, ml->coordination.machine_public_key, &key_len);
        if (ret == ESP_OK && key_len == 32) {
            ESP_LOGI(TAG, "Loaded existing machine key from NVS");
            nvs_close(nvs);
            return ESP_OK;
        }
    }

    ESP_LOGI(TAG, "No machine key in NVS, generating new one");
    need_save = true;

generate_new:
    // Generate new machine key (Curve25519 keypair)
    {
        noise_state_t temp_noise;
        noise_init(&temp_noise, NULL, get_server_public_key(), TAILSCALE_PROTOCOL_VERSION);

        // Store machine keys
        memcpy(ml->coordination.machine_private_key, temp_noise.local_static_private, 32);
        memcpy(ml->coordination.machine_public_key, temp_noise.local_static_public, 32);
    }

    // Save to NVS if we opened it successfully
    if (need_save && nvs != 0) {
        ret = nvs_set_blob(nvs, NVS_KEY_MACHINE_PRI, ml->coordination.machine_private_key, 32);
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_MACHINE_PUB, ml->coordination.machine_public_key, 32);
        }
        if (ret == ESP_OK) {
            ret = nvs_commit(nvs);
        }
        if (ret == ESP_OK) {
            ESP_LOGI(TAG, "Saved new machine key to NVS");
        } else {
            ESP_LOGW(TAG, "Failed to save machine key to NVS: %d", ret);
        }
        nvs_close(nvs);
    }

    return ESP_OK;
}

esp_err_t microlink_coordination_init(microlink_t *ml) {
    ESP_LOGI(TAG, "Initializing coordination client");

    memset(&ml->coordination, 0, sizeof(microlink_coordination_t));
    ml->coordination.socket = -1;  // Invalid socket initially

    // === Dual-Core PSRAM Fix: Initialize synchronization primitives ===
    ml->coordination.mutex = xSemaphoreCreateMutex();
    if (ml->coordination.mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create coordination mutex");
        return ESP_ERR_NO_MEM;
    }

    // Allocate 64KB buffer from PSRAM for large MapResponses
    // This is the key fix - using external PSRAM instead of limited SRAM
    ml->coordination.psram_buffer = heap_caps_malloc(MICROLINK_COORD_BUFFER_SIZE, MALLOC_CAP_SPIRAM);
    if (ml->coordination.psram_buffer == NULL) {
        ESP_LOGW(TAG, "PSRAM allocation failed, falling back to regular heap");
        ml->coordination.psram_buffer = malloc(MICROLINK_COORD_BUFFER_SIZE);
        if (ml->coordination.psram_buffer == NULL) {
            ESP_LOGE(TAG, "Failed to allocate coordination buffer");
            vSemaphoreDelete(ml->coordination.mutex);
            ml->coordination.mutex = NULL;
            return ESP_ERR_NO_MEM;
        }
    } else {
        ESP_LOGI(TAG, "Allocated %d bytes from PSRAM for coordination buffer", MICROLINK_COORD_BUFFER_SIZE);
    }

    ml->coordination.poll_task_handle = NULL;
    ml->coordination.poll_task_running = false;
    ml->coordination.connection_error = false;
    ml->coordination.frames_processed = 0;

    // Load or generate machine key (persisted in NVS)
    load_or_generate_machine_key(ml);

    // Create machine key string (base64-encoded public key with "mkey:" prefix)
    // For now, use hex representation
    snprintf(ml->coordination.machine_key, sizeof(ml->coordination.machine_key),
             "mkey:%02x%02x%02x%02x",
             ml->coordination.machine_public_key[0],
             ml->coordination.machine_public_key[1],
             ml->coordination.machine_public_key[2],
             ml->coordination.machine_public_key[3]);

    ESP_LOGI(TAG, "Machine key: %s", ml->coordination.machine_key);
    ESP_LOGI(TAG, "Coordination client initialized (dual-core PSRAM mode)");

    return ESP_OK;
}

esp_err_t microlink_coordination_deinit(microlink_t *ml) {
    ESP_LOGI(TAG, "Deinitializing coordination client");

    // Stop the poll task first if running
    microlink_coordination_stop_poll_task(ml);

    // Free PSRAM buffer
    if (ml->coordination.psram_buffer != NULL) {
        heap_caps_free(ml->coordination.psram_buffer);
        ml->coordination.psram_buffer = NULL;
    }

    // Delete mutex
    if (ml->coordination.mutex != NULL) {
        vSemaphoreDelete(ml->coordination.mutex);
        ml->coordination.mutex = NULL;
    }

    // Close socket if open
    if (ml->coordination.socket >= 0) {
        close(ml->coordination.socket);
        ml->coordination.socket = -1;
    }

    memset(&ml->coordination, 0, sizeof(microlink_coordination_t));
    ml->coordination.socket = -1;

    return ESP_OK;
}

esp_err_t microlink_coordination_register(microlink_t *ml) {
    ESP_LOGI(TAG, "Registering device with Tailscale");
    ESP_LOGI(TAG, "Device: %s, Auth key: %s",
             ml->config.device_name,
             ml->config.auth_key ? "present" : "missing");

    if (!ml->config.auth_key || strlen(ml->config.auth_key) == 0) {
        ESP_LOGE(TAG, "Auth key is required for registration");
        return ESP_ERR_INVALID_ARG;
    }

    // Check heap memory before TLS operations
    ESP_LOGI(TAG, "Free heap before TLS: %u bytes (min: %u)",
             (unsigned int)esp_get_free_heap_size(),
             (unsigned int)esp_get_minimum_free_heap_size());

    esp_err_t ret = ESP_FAIL;
    int sock = -1;  // Initialize socket to -1 for cleanup safety

    // Allocate large buffers on heap to reduce stack usage
    uint8_t *msg1 = NULL;
    uint8_t *msg2 = NULL;
    uint8_t *response_payload = NULL;
    char *payload = NULL;

    // Allocate buffers
    msg1 = malloc(1024);
    msg2 = malloc(2048);
    response_payload = malloc(1024);
    payload = malloc(512);

    if (!msg1 || !msg2 || !response_payload || !payload) {
        ESP_LOGE(TAG, "Failed to allocate buffers");
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    // Initialize Noise handshake with Tailscale protocol version
    // Server public key is fetched from /key endpoint (supports Headscale/Ionscale)
    noise_state_t noise;
    noise_init(&noise, ml->coordination.machine_private_key,
               get_server_public_key(), TAILSCALE_PROTOCOL_VERSION);

    // Build registration payload (JSON)
    int payload_len = snprintf(payload, 512,
        "{\"authKey\":\"%s\",\"hostName\":\"%s\",\"capabilities\":[\"ssh\",\"https\"]}",
        ml->config.auth_key,
        ml->config.device_name);

    if (payload_len >= 512) {
        ESP_LOGE(TAG, "Payload too large");
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    // Generate Noise handshake message 1 (101 bytes: 5-byte header + 96-byte Noise payload)
    // NOTE: Tailscale does NOT include application payload in Noise message 1
    // The registration JSON will be sent AFTER the handshake completes
    size_t msg1_len = noise_write_message_1(&noise, TAILSCALE_PROTOCOL_VERSION, msg1);

    ESP_LOGI(TAG, "Generated Noise message 1: %u bytes (should be 101)", (unsigned int)msg1_len);
    ESP_LOGI(TAG, "Registration payload will be sent after handshake: %s", payload);

    // Step 1: Establish plain TCP connection to port 80 (HTTP mode - happy path)
    // Tailscale uses HTTP on port 80 as the primary protocol, with HTTPS on 443 as fallback
    // After HTTP 101, the connection becomes raw TCP with Noise encryption (no TLS double-encryption)
    ESP_LOGI(TAG, "Connecting to %s:80 via HTTP (plain TCP)", TAILSCALE_CONTROL_HOST);

    // Create TCP socket
    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = 0;  // Will be resolved via getaddrinfo
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(80);

    // Resolve hostname
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res;
    int err = getaddrinfo(TAILSCALE_CONTROL_HOST, "80", &hints, &res);
    if (err != 0 || res == NULL) {
        ESP_LOGE(TAG, "DNS lookup failed: %d", err);
        ret = ESP_FAIL;
        goto cleanup;
    }

    dest_addr.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %d", errno);
        ret = ESP_FAIL;
        goto cleanup;
    }

    // Set socket timeout
    struct timeval timeout = {
        .tv_sec = 10,
        .tv_usec = 0,
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    // Enable TCP keepalive to prevent NAT/firewall timeout (25 seconds)
    // This is CRITICAL for maintaining connection through NAT boxes
    int keepalive = 1;
    int keepidle = 25;   // Start keepalive after 25 seconds of idle
    int keepintvl = 10;  // Send keepalive every 10 seconds after that
    int keepcnt = 3;     // Give up after 3 missed keepalives
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    // Connect
    err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0) {
        ESP_LOGE(TAG, "Socket connect failed: %d", errno);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(TAG, "TCP connection established to %s:80", TAILSCALE_CONTROL_HOST);

    // Step 2: Base64-encode Noise message 1 for X-Tailscale-Handshake header
    size_t b64_len;
    mbedtls_base64_encode(NULL, 0, &b64_len, msg1, msg1_len);

    char *msg1_b64 = (char *)malloc(b64_len + 1);
    if (!msg1_b64) {
        ESP_LOGE(TAG, "Failed to allocate base64 buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    ret = mbedtls_base64_encode((unsigned char *)msg1_b64, b64_len, &b64_len,
                                msg1, msg1_len);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to base64 encode: %d", ret);
        free(msg1_b64);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }
    msg1_b64[b64_len] = '\0';

    ESP_LOGI(TAG, "Base64-encoded Noise message 1: %u bytes -> %u bytes", (unsigned int)msg1_len, (unsigned int)b64_len);

    // Step 3: Send HTTP POST with X-Tailscale-Handshake header
    size_t http_req_size = 512 + b64_len;
    char *http_request = (char *)malloc(http_req_size);
    if (!http_request) {
        ESP_LOGE(TAG, "Failed to allocate HTTP request buffer");
        free(msg1_b64);
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    int request_len = snprintf(http_request, http_req_size,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: tailscale-control-protocol\r\n"
        "Connection: Upgrade\r\n"
        "User-Agent: Tailscale\r\n"
        "X-Tailscale-Handshake: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        TAILSCALE_TS2021_PATH,
        TAILSCALE_CONTROL_HOST,
        msg1_b64);

    free(msg1_b64);

    ESP_LOGI(TAG, "Sending HTTP Upgrade with X-Tailscale-Handshake (%d bytes)", request_len);

    // Send HTTP request over plain TCP
    int written = send(sock, http_request, request_len, 0);
    free(http_request);
    if (written < request_len) {
        ESP_LOGE(TAG, "Failed to send HTTP request: %d (errno: %d)", written, errno);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Sent HTTP Upgrade request (waiting for HTTP 101...)");

    // Step 4: Read HTTP 101 response
    // Allocate larger buffer in case Noise message 2 comes with HTTP 101
    char *http_response = (char *)malloc(2048);
    if (!http_response) {
        ESP_LOGE(TAG, "Failed to allocate HTTP response buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    // Read HTTP 101 response - may include Noise message in same read
    int read_len = recv(sock, http_response, 2048, 0);
    if (read_len <= 0) {
        ESP_LOGE(TAG, "Failed to read HTTP response: %d (errno: %d)", read_len, errno);
        free(http_response);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(TAG, "Received HTTP response (%d bytes total)", read_len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, http_response, read_len < 128 ? read_len : 128, ESP_LOG_INFO);

    // Null-terminate for string operations (but data may continue as binary)
    http_response[read_len < 2047 ? read_len : 2047] = '\0';

    // Declare msg2_len early so it can be used throughout
    int msg2_len = 0;

    // Find end of HTTP headers to print them separately
    char *headers_end = strstr(http_response, "\r\n\r\n");
    if (headers_end) {
        *headers_end = '\0';  // Temporarily terminate at end of headers
        ESP_LOGI(TAG, "HTTP headers:\n%s", http_response);

        // Check for X-Tailscale-Response header (Noise message 2 might be here)
        char *response_header = strstr(http_response, "X-Tailscale-Response:");
        if (response_header) {
            response_header += strlen("X-Tailscale-Response:");
            while (*response_header == ' ') response_header++;  // Skip spaces
            char *response_end = strstr(response_header, "\r\n");
            if (response_end) {
                size_t response_b64_len = response_end - response_header;
                char *response_b64 = strndup(response_header, response_b64_len);

                ESP_LOGI(TAG, "Found X-Tailscale-Response header (%u bytes base64)", (unsigned int)response_b64_len);

                // Base64 decode to get Noise message 2
                size_t decoded_len;
                ret = mbedtls_base64_decode(msg2, 2048, &decoded_len,
                                            (const unsigned char *)response_b64, response_b64_len);
                free(response_b64);

                if (ret == 0) {
                    msg2_len = decoded_len;
                    ESP_LOGI(TAG, "Decoded Noise message 2 from header: %d bytes", msg2_len);
                    ESP_LOG_BUFFER_HEX_LEVEL(TAG, msg2, msg2_len < 64 ? msg2_len : 64, ESP_LOG_INFO);
                } else {
                    ESP_LOGW(TAG, "Failed to base64 decode X-Tailscale-Response: %d", ret);
                }
            }
        }

        *headers_end = '\r';  // Restore for later parsing
    } else {
        ESP_LOGI(TAG, "HTTP headers:\n%s", http_response);
    }

    // Parse HTTP status line
    int status_code = 0;
    if (sscanf(http_response, "HTTP/1.%*d %d", &status_code) != 1) {
        ESP_LOGE(TAG, "Failed to parse HTTP status");
        free(http_response);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(TAG, "HTTP status: %d", status_code);

    if (status_code != 101) {
        // Print error response body
        char *body_start = strstr(http_response, "\r\n\r\n");
        if (body_start) {
            body_start += 4;
            ESP_LOGE(TAG, "Server error (HTTP %d): %s", status_code, body_start);
        } else {
            ESP_LOGE(TAG, "Expected HTTP 101, got %d", status_code);
        }
        free(http_response);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    // Find any data after HTTP headers (check if already in the initial read)
    char *body_start = strstr(http_response, "\r\n\r\n");

    if (body_start && msg2_len == 0) {  // Only check body if we didn't get it from header
        body_start += 4;  // Skip past \r\n\r\n
        msg2_len = read_len - (body_start - http_response);

        if (msg2_len > 0) {
            ESP_LOGI(TAG, "Found %d bytes after HTTP headers", msg2_len);
            memcpy(msg2, body_start, msg2_len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, msg2, msg2_len < 64 ? msg2_len : 64, ESP_LOG_INFO);
        }
    }

    free(http_response);

    // Protocol upgraded! Continue reading from raw TCP connection
    // After HTTP 101, the connection becomes plain TCP with Noise encryption (no TLS layer)
    // This is the "happy path" - HTTP on port 80 stays as plain TCP
    ESP_LOGI(TAG, "Protocol upgraded to tailscale-control-protocol");
    ESP_LOGI(TAG, "Socket is now a Noise-encrypted connection (raw TCP, no TLS)");

    // Check if we already have Noise message 2 from the HTTP response
    // (Server often sends it immediately after HTTP 101 in same TCP segment)
    if (msg2_len >= 3) {
        // We already have data - parse the header from buffered data
        ESP_LOGI(TAG, "Using %d bytes of Noise message 2 already received with HTTP 101", msg2_len);

        // Parse frame header from buffered data
        uint8_t msg_type = msg2[0];
        uint16_t frame_payload_len = (msg2[1] << 8) | msg2[2];

        ESP_LOGI(TAG, "Buffered Noise frame: type=0x%02x, length=%d", msg_type, frame_payload_len);

        if (msg_type != 0x02) {
            ESP_LOGW(TAG, "Unexpected Noise message type: 0x%02x (expected 0x02)", msg_type);
        }

        // Check if we have the complete message
        int total_expected = 3 + frame_payload_len;  // header + payload
        if (msg2_len < total_expected) {
            ESP_LOGW(TAG, "Incomplete message: have %d, need %d - reading more from socket",
                     msg2_len, total_expected);

            // Read remaining data from socket
            for (int retry = 0; retry < 15 && msg2_len < total_expected; retry++) {
                int n = recv(sock, msg2 + msg2_len, total_expected - msg2_len, 0);
                if (n > 0) {
                    msg2_len += n;
                } else if (n < 0) {
                    ESP_LOGW(TAG, "Read error: %d (errno: %d)", n, errno);
                }
                if (msg2_len < total_expected) {
                    vTaskDelay(pdMS_TO_TICKS(100));
                }
            }
        }

        if (msg2_len >= total_expected) {
            // Check if there's extra data after message 2 (server might send more)
            int extra_data_len = msg2_len - total_expected;
            int extra_data_offset = total_expected;  // Save offset to extra data
            if (extra_data_len > 0) {
                ESP_LOGI(TAG, "Found %d extra bytes after Noise message 2:", extra_data_len);
                ESP_LOG_BUFFER_HEX_LEVEL(TAG, msg2 + total_expected,
                                         extra_data_len < 64 ? extra_data_len : 64, ESP_LOG_INFO);
            }

            // Save the extra data before moving msg2 payload
            uint8_t *extra_data = NULL;
            if (extra_data_len > 0) {
                extra_data = malloc(extra_data_len);
                if (extra_data) {
                    memcpy(extra_data, msg2 + extra_data_offset, extra_data_len);
                }
            }

            // Move payload to beginning of buffer (skip 3-byte header)
            memmove(msg2, msg2 + 3, frame_payload_len);
            msg2_len = frame_payload_len;
            ESP_LOGI(TAG, "Complete Noise message 2 payload: %d bytes", msg2_len);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, msg2, msg2_len < 64 ? msg2_len : 64, ESP_LOG_INFO);

            // Count how many transport frames are in the extra data
            // These are frames the server sent proactively after handshake
            // We need to increment our rx_nonce for each frame we skip
            // because the server already sent them and incremented its tx_nonce
            int skipped_frame_count = 0;
            if (extra_data && extra_data_len >= 3) {
                int offset = 0;
                while (offset + 3 <= extra_data_len) {
                    uint8_t frame_type = extra_data[offset];
                    uint16_t frame_len = (extra_data[offset + 1] << 8) | extra_data[offset + 2];
                    ESP_LOGI(TAG, "Extra frame %d: type=0x%02x, len=%u", skipped_frame_count, frame_type, frame_len);

                    if (offset + 3 + frame_len > extra_data_len) {
                        ESP_LOGW(TAG, "Incomplete extra frame at offset %d", offset);
                        break;
                    }

                    skipped_frame_count++;
                    offset += 3 + frame_len;
                }
                ESP_LOGI(TAG, "Server sent %d proactive transport frames - will decrypt after handshake", skipped_frame_count);
                // Store extra data globally for decryption after handshake
                if (g_server_extra_data) {
                    free(g_server_extra_data);
                }
                g_server_extra_data = extra_data;
                g_server_extra_data_len = extra_data_len;
                extra_data = NULL;  // Don't free it
            }

            // Store the count to adjust rx_nonce after handshake completes
            g_skipped_server_frames = skipped_frame_count;

            // Free extra_data if not stored globally
            if (extra_data) {
                free(extra_data);
            }
        } else {
            ESP_LOGE(TAG, "Failed to get complete Noise message 2 (have %d/%d)", msg2_len, total_expected);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }
    } else {
        // No data buffered - read from socket
        ESP_LOGI(TAG, "No buffered data, reading Noise message 2 from socket");
        vTaskDelay(pdMS_TO_TICKS(200));  // Give server time to send

        // Read the 3-byte Noise frame header from raw socket
        uint8_t frame_header[3];
        int header_read = 0;

        for (int retry = 0; retry < 15 && header_read < 3; retry++) {
            int n = recv(sock, frame_header + header_read, 3 - header_read, 0);
            if (n > 0) {
                header_read += n;
                if (header_read == 3) {
                    ESP_LOGI(TAG, "Read Noise frame header: type=0x%02x, length=%d",
                             frame_header[0],
                             (frame_header[1] << 8) | frame_header[2]);
                    break;
                }
            } else if (n < 0) {
                ESP_LOGW(TAG, "Noise frame header read error: %d (errno: %d)", n, errno);
            } else {
                ESP_LOGD(TAG, "No data yet, retry %d/15", retry + 1);
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (header_read != 3) {
            ESP_LOGE(TAG, "Failed to read complete Noise frame header (got %d/3 bytes)", header_read);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }

        // Verify message type (should be 0x02 for Noise response)
        if (frame_header[0] != 0x02) {
            ESP_LOGW(TAG, "Unexpected Noise message type: 0x%02x (expected 0x02)", frame_header[0]);
        }

        // Get frame payload length (big-endian uint16)
        uint16_t frame_payload_len = (frame_header[1] << 8) | frame_header[2];
        ESP_LOGI(TAG, "Noise message 2 payload length: %d bytes", frame_payload_len);

        if (frame_payload_len > 2048) {
            ESP_LOGE(TAG, "Payload too large: %d bytes", frame_payload_len);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }

        // Read the payload from raw socket
        msg2_len = 0;
        for (int retry = 0; retry < 15 && msg2_len < frame_payload_len; retry++) {
            int n = recv(sock, msg2 + msg2_len, frame_payload_len - msg2_len, 0);
            if (n > 0) {
                msg2_len += n;
                if (msg2_len == frame_payload_len) {
                    ESP_LOGI(TAG, "Read complete Noise message 2 payload: %d bytes", msg2_len);
                    ESP_LOG_BUFFER_HEX_LEVEL(TAG, msg2, msg2_len < 64 ? msg2_len : 64, ESP_LOG_INFO);
                    break;
                }
            } else if (n < 0) {
                ESP_LOGW(TAG, "Payload read error: %d (errno: %d)", n, errno);
            } else {
                ESP_LOGD(TAG, "No payload data yet, retry %d/15", retry + 1);
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        if (msg2_len != frame_payload_len) {
            ESP_LOGE(TAG, "Failed to read complete payload (got %d/%d bytes)", msg2_len, frame_payload_len);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }
    }

    // Socket is now ready for ongoing Noise-encrypted communication
    // Store it for future use in the coordination context

    ESP_LOGI(TAG, "Received Noise handshake message 2 (%d bytes)", msg2_len);

    // Parse message 2 and derive transport keys
    // Note: message 2 has empty payload (just handshake completion)
    size_t handshake_response_len;
    ret = noise_read_message_2(&noise, msg2, msg2_len,
                               response_payload, &handshake_response_len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to parse handshake message 2");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Handshake complete! Transport keys derived.");
    ESP_LOGI(TAG, "Handshake response was %u bytes (should be 0 for IK pattern)", (unsigned int)handshake_response_len);
    log_hex("tx_key", noise.tx_key, 32);
    log_hex("rx_key", noise.rx_key, 32);

    // Process proactive frames from server
    // The server sends EarlyNoise + HTTP/2 preface immediately after handshake
    //
    // IMPORTANT DISCOVERY: After EarlyNoise (frame 0), the remaining "frames" (1, 2, 3)
    // fail to decrypt with any nonce/key combination. This suggests they might be:
    // 1. Using a different encryption scheme
    // 2. Part of a larger message we're incorrectly parsing
    // 3. Or simply garbage/padding we should skip
    //
    // Strategy: Only process EarlyNoise, skip the rest, and let rx_nonce=1 for real responses
    if (g_server_extra_data && g_server_extra_data_len > 0) {
        ESP_LOGI(TAG, "=== Processing %d bytes of server proactive data ===", g_server_extra_data_len);
        log_hex("Raw extra data", g_server_extra_data, g_server_extra_data_len < 64 ? g_server_extra_data_len : 64);

        // Count total frames for logging
        int total_frames = 0;
        int count_offset = 0;
        while (count_offset + 3 <= g_server_extra_data_len) {
            uint16_t flen = (g_server_extra_data[count_offset + 1] << 8) | g_server_extra_data[count_offset + 2];
            if (count_offset + 3 + flen > g_server_extra_data_len) break;
            total_frames++;
            count_offset += 3 + flen;
        }
        ESP_LOGI(TAG, "Total proactive frames detected: %d", total_frames);

        // Process frames
        int offset = 0;
        int frame_idx = 0;
        bool early_noise_found = false;

        while (offset + 3 <= g_server_extra_data_len) {
            uint8_t frame_type = g_server_extra_data[offset];
            uint16_t frame_len = (g_server_extra_data[offset + 1] << 8) | g_server_extra_data[offset + 2];

            if (offset + 3 + frame_len > g_server_extra_data_len) {
                ESP_LOGW(TAG, "Incomplete frame %d at offset %d", frame_idx, offset);
                break;
            }

            ESP_LOGI(TAG, "Proactive frame %d: type=0x%02x, len=%u, nonce=%lu",
                     frame_idx, frame_type, frame_len, (unsigned long)noise.rx_nonce);

            if (frame_type == 0x04 && frame_len >= NOISE_MAC_LEN) {
                uint8_t *ciphertext = g_server_extra_data + offset + 3;
                size_t plaintext_len = frame_len - NOISE_MAC_LEN;
                uint8_t *plaintext = malloc(plaintext_len + 1);

                if (plaintext) {
                    // Try current nonce first
                    esp_err_t dec_ret = noise_decrypt(noise.rx_key, noise.rx_nonce,
                                                      NULL, 0,
                                                      ciphertext, frame_len,
                                                      plaintext);

                    // If failed, try multiple nonces and both keys
                    bool decrypted = (dec_ret == ESP_OK);
                    uint64_t used_nonce = noise.rx_nonce;
                    const char *used_key = "rx_key";

                    if (!decrypted && frame_idx > 0) {
                        ESP_LOGI(TAG, "  Trying alternative nonces/keys for frame %d...", frame_idx);

                        // EarlyNoise format insight: After the 5-byte magic, there's:
                        // - 4 bytes: payload length (big-endian uint32)
                        // - N bytes: JSON payload
                        // These may be in the same frame or split across frames
                        // The nonces SHOULD increment per frame, but let's try more variations

                        // Try nonces 0-10 with rx_key
                        for (uint64_t try_nonce = 0; try_nonce <= 10 && !decrypted; try_nonce++) {
                            if (try_nonce == noise.rx_nonce) continue;  // Already tried
                            dec_ret = noise_decrypt(noise.rx_key, try_nonce,
                                                   NULL, 0,
                                                   ciphertext, frame_len,
                                                   plaintext);
                            if (dec_ret == ESP_OK) {
                                decrypted = true;
                                used_nonce = try_nonce;
                                used_key = "rx_key";
                                ESP_LOGI(TAG, "  SUCCESS with rx_key nonce=%lu", (unsigned long)try_nonce);
                            }
                        }

                        // Try nonces 0-5 with tx_key
                        for (uint64_t try_nonce = 0; try_nonce <= 5 && !decrypted; try_nonce++) {
                            dec_ret = noise_decrypt(noise.tx_key, try_nonce,
                                                   NULL, 0,
                                                   ciphertext, frame_len,
                                                   plaintext);
                            if (dec_ret == ESP_OK) {
                                decrypted = true;
                                used_nonce = try_nonce;
                                used_key = "tx_key";
                                ESP_LOGI(TAG, "  SUCCESS with tx_key nonce=%lu", (unsigned long)try_nonce);
                            }
                        }
                    }

                    if (decrypted) {
                        plaintext[plaintext_len] = '\0';
                        ESP_LOGI(TAG, "  Decrypted frame %d (%u bytes) with %s nonce=%lu:",
                                 frame_idx, (unsigned int)plaintext_len, used_key, (unsigned long)used_nonce);
                        log_hex("  Plaintext", plaintext, plaintext_len < 64 ? plaintext_len : 64);

                        // Check for EarlyNoise magic
                        if (plaintext_len >= 5 && memcmp(plaintext, "\xff\xff\xffTS", 5) == 0) {
                            ESP_LOGI(TAG, "  *** EarlyNoise magic confirmed! ***");
                            early_noise_found = true;
                        }

                        // Check for EarlyNoise JSON with nodeKeyChallenge
                        // Format: {"nodeKeyChallenge":"chalpub:base64..."}
                        if (plaintext_len > 20 && plaintext[0] == '{') {
                            // Try to parse as JSON
                            cJSON *early_json = cJSON_Parse((const char *)plaintext);
                            if (early_json) {
                                cJSON *challenge = cJSON_GetObjectItem(early_json, "nodeKeyChallenge");
                                if (challenge && cJSON_IsString(challenge)) {
                                    const char *chal_str = challenge->valuestring;
                                    ESP_LOGI(TAG, "  *** Found nodeKeyChallenge: %.40s... ***", chal_str);

                                    // Parse "chalpub:hex..." format (64 hex chars = 32 bytes)
                                    if (strncmp(chal_str, "chalpub:", 8) == 0) {
                                        const char *hex_str = chal_str + 8;
                                        size_t hex_len = strlen(hex_str);

                                        // Tailscale uses HEX encoding for challenge public keys (not base64)
                                        // 64 hex characters = 32 bytes
                                        if (hex_len >= 64) {
                                            // Hex decode the challenge public key
                                            bool decode_ok = true;
                                            for (int i = 0; i < 32 && decode_ok; i++) {
                                                char hex_byte[3] = {hex_str[i*2], hex_str[i*2 + 1], '\0'};
                                                char *endptr;
                                                long val = strtol(hex_byte, &endptr, 16);
                                                if (*endptr != '\0') {
                                                    decode_ok = false;
                                                } else {
                                                    g_node_key_challenge[i] = (uint8_t)val;
                                                }
                                            }

                                            if (decode_ok) {
                                                g_has_node_key_challenge = true;
                                                ESP_LOGI(TAG, "  *** NodeKeyChallenge hex-decoded (32 bytes) ***");
                                                log_hex("  Challenge pubkey", g_node_key_challenge, 32);
                                            } else {
                                                ESP_LOGW(TAG, "  Failed to hex-decode challenge");
                                            }
                                        } else {
                                            ESP_LOGW(TAG, "  Challenge hex string too short: %u chars (need 64)", (unsigned int)hex_len);
                                        }
                                    }
                                }
                                cJSON_Delete(early_json);
                            }
                        }

                        // Check for HTTP/2 frames (after EarlyNoise)
                        if (plaintext_len >= 9 && frame_idx > 0) {
                            uint32_t h2_len = (plaintext[0] << 16) | (plaintext[1] << 8) | plaintext[2];
                            uint8_t h2_type = plaintext[3];
                            uint8_t h2_flags = plaintext[4];
                            ESP_LOGI(TAG, "  HTTP/2 frame: type=%u, len=%lu, flags=0x%02x",
                                     h2_type, (unsigned long)h2_len, h2_flags);

                            // Type 4 = SETTINGS, Type 7 = GOAWAY, Type 6 = PING
                            if (h2_type == 4 && h2_len > 0) {
                                ESP_LOGI(TAG, "  -> Server SETTINGS frame with %lu bytes", (unsigned long)h2_len);
                                // Parse SETTINGS payload (starts at byte 9 of HTTP/2 frame)
                                const uint8_t *settings = plaintext + 9;
                                uint32_t settings_len = h2_len;
                                for (uint32_t i = 0; i + 6 <= settings_len; i += 6) {
                                    uint16_t id = (settings[i] << 8) | settings[i + 1];
                                    uint32_t val = (settings[i + 2] << 24) | (settings[i + 3] << 16) |
                                                   (settings[i + 4] << 8) | settings[i + 5];
                                    const char *name = "UNKNOWN";
                                    switch (id) {
                                        case 1: name = "HEADER_TABLE_SIZE"; break;
                                        case 2: name = "ENABLE_PUSH"; break;
                                        case 3: name = "MAX_CONCURRENT_STREAMS"; break;
                                        case 4: name = "INITIAL_WINDOW_SIZE"; break;
                                        case 5: name = "MAX_FRAME_SIZE"; break;
                                        case 6: name = "MAX_HEADER_LIST_SIZE"; break;
                                    }
                                    ESP_LOGI(TAG, "    SETTING %s (0x%x) = %lu", name, id, (unsigned long)val);
                                }
                            } else if (h2_type == 4) {
                                ESP_LOGI(TAG, "  -> Server SETTINGS ACK");
                            } else if (h2_type == 7) {
                                ESP_LOGW(TAG, "  -> Server GOAWAY frame!");
                            }
                        }

                        // Check if it looks like raw HTTP/2 preface
                        if (plaintext_len >= 24 && memcmp(plaintext, "PRI * HTTP/2.0", 14) == 0) {
                            ESP_LOGI(TAG, "  *** Server HTTP/2 connection preface! ***");
                        }

                        noise.rx_nonce++;
                    } else {
                        // Log the raw ciphertext for analysis
                        ESP_LOGE(TAG, "  Failed to decrypt frame %d (len=%u) with ANY nonce/key!",
                                 frame_idx, frame_len);
                        log_hex("  Ciphertext", ciphertext, frame_len < 32 ? frame_len : 32);

                        // Maybe it's not encrypted? Try interpreting as raw data
                        if (frame_len >= 9) {
                            // Check if it looks like HTTP/2 frame header
                            uint32_t maybe_h2_len = (ciphertext[0] << 16) | (ciphertext[1] << 8) | ciphertext[2];
                            uint8_t maybe_h2_type = ciphertext[3];
                            ESP_LOGI(TAG, "  As raw HTTP/2: len=%lu, type=%u",
                                     (unsigned long)maybe_h2_len, maybe_h2_type);
                        }

                        // Still increment nonce to stay in sync
                        noise.rx_nonce++;
                    }

                    free(plaintext);
                }
            } else {
                ESP_LOGW(TAG, "  Unexpected frame type 0x%02x or too short", frame_type);
            }

            offset += 3 + frame_len;
            frame_idx++;
        }

        ESP_LOGI(TAG, "Processed %d proactive frames, rx_nonce now=%lu, early_noise=%d",
                 frame_idx, (unsigned long)noise.rx_nonce, early_noise_found);

        free(g_server_extra_data);
        g_server_extra_data = NULL;
        g_server_extra_data_len = 0;
        g_skipped_server_frames = 0;
    } else if (g_skipped_server_frames > 0) {
        ESP_LOGI(TAG, "Adjusting rx_nonce by %d for skipped frames", g_skipped_server_frames);
        noise.rx_nonce = g_skipped_server_frames;
        g_skipped_server_frames = 0;
    }

    // After Noise handshake, establish HTTP/2 connection over the encrypted channel
    // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + SETTINGS frame
    ESP_LOGI(TAG, "Sending HTTP/2 connection preface over Noise...");

    // HTTP/2 connection preface (24 bytes)
    static const char H2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    // HTTP/2 SETTINGS frame (empty settings, 9-byte header only)
    // Format: length(3) + type(1) + flags(1) + stream_id(4)
    static const uint8_t H2_SETTINGS[] = {
        0x00, 0x00, 0x00,  // Length: 0 (no settings)
        0x04,              // Type: SETTINGS
        0x00,              // Flags: none
        0x00, 0x00, 0x00, 0x00  // Stream ID: 0 (connection)
    };
    // HTTP/2 SETTINGS ACK (acknowledge server's settings)
    static const uint8_t H2_SETTINGS_ACK[] = {
        0x00, 0x00, 0x00,  // Length: 0
        0x04,              // Type: SETTINGS
        0x01,              // Flags: ACK
        0x00, 0x00, 0x00, 0x00  // Stream ID: 0
    };

    // Combine preface + settings + settings_ack
    size_t h2_init_len = sizeof(H2_PREFACE) - 1 + sizeof(H2_SETTINGS) + sizeof(H2_SETTINGS_ACK);
    uint8_t *h2_init = malloc(h2_init_len);
    if (!h2_init) {
        ESP_LOGE(TAG, "Failed to allocate HTTP/2 init buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    memcpy(h2_init, H2_PREFACE, sizeof(H2_PREFACE) - 1);
    memcpy(h2_init + sizeof(H2_PREFACE) - 1, H2_SETTINGS, sizeof(H2_SETTINGS));
    memcpy(h2_init + sizeof(H2_PREFACE) - 1 + sizeof(H2_SETTINGS), H2_SETTINGS_ACK, sizeof(H2_SETTINGS_ACK));

    ESP_LOGI(TAG, "HTTP/2 init data (%u bytes):", (unsigned int)h2_init_len);
    log_hex("H2 init", h2_init, h2_init_len);

    // Encrypt and send HTTP/2 preface as one Noise frame
    size_t encrypted_len = h2_init_len + NOISE_MAC_LEN;
    uint8_t *encrypted_payload = malloc(encrypted_len + 3);
    if (!encrypted_payload) {
        free(h2_init);
        ESP_LOGE(TAG, "Failed to allocate encrypted buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    // Noise frame header
    encrypted_payload[0] = 0x04;  // Type 4 = transport data
    encrypted_payload[1] = (encrypted_len >> 8) & 0xFF;
    encrypted_payload[2] = encrypted_len & 0xFF;

    ESP_LOGI(TAG, "Encrypting HTTP/2 preface with tx_nonce=%lu", (unsigned long)noise.tx_nonce);
    log_hex("tx_key for encryption", noise.tx_key, 32);

    ret = noise_encrypt(noise.tx_key, noise.tx_nonce++,
                       NULL, 0,
                       h2_init, h2_init_len,
                       encrypted_payload + 3);
    free(h2_init);

    ESP_LOGI(TAG, "Encrypted HTTP/2 preface:");
    log_hex("Encrypted payload", encrypted_payload + 3, encrypted_len);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to encrypt HTTP/2 preface");
        free(encrypted_payload);
        close(sock);
        goto cleanup;
    }

    int total_send_len = 3 + encrypted_len;
    ESP_LOGI(TAG, "Sending encrypted HTTP/2 preface (%d bytes)", total_send_len);

    int sent = send(sock, encrypted_payload, total_send_len, 0);
    free(encrypted_payload);

    if (sent != total_send_len) {
        ESP_LOGE(TAG, "Failed to send HTTP/2 preface: %d (errno: %d)", sent, errno);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    // Read server's HTTP/2 preface response (SETTINGS frames etc.)
    // The server will respond to our HTTP/2 preface with its own preface
    // We MUST read and decrypt these frames to keep nonce in sync
    ESP_LOGI(TAG, "Reading server HTTP/2 preface frames (rx_nonce=%lu)...",
             (unsigned long)noise.rx_nonce);

    // Give server time to respond
    vTaskDelay(pdMS_TO_TICKS(200));

    // Read all available frames from server
    int server_frames_read = 0;
    for (int frame_attempt = 0; frame_attempt < 5; frame_attempt++) {
        uint8_t frame_hdr[3];
        int hdr_read = 0;

        // Non-blocking check for more data
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;  // 200ms timeout
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int n = recv(sock, frame_hdr, 3, MSG_PEEK);
        if (n < 3) {
            ESP_LOGI(TAG, "No more server frames available (got %d bytes)", n);
            break;
        }

        // Actually read the header
        hdr_read = recv(sock, frame_hdr, 3, 0);
        if (hdr_read != 3) {
            ESP_LOGW(TAG, "Failed to read frame header");
            break;
        }

        uint8_t ftype = frame_hdr[0];
        uint16_t flen = (frame_hdr[1] << 8) | frame_hdr[2];

        ESP_LOGI(TAG, "Server frame %d: type=0x%02x, len=%u", frame_attempt, ftype, flen);

        if (flen > 4096) {
            ESP_LOGE(TAG, "Frame too large, aborting");
            break;
        }

        // Read the frame payload
        uint8_t *frame_data = malloc(flen);
        if (!frame_data) {
            ESP_LOGE(TAG, "Failed to allocate frame buffer");
            break;
        }

        int payload_read = 0;
        while (payload_read < flen) {
            n = recv(sock, frame_data + payload_read, flen - payload_read, 0);
            if (n > 0) {
                payload_read += n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            } else {
                vTaskDelay(pdMS_TO_TICKS(50));
            }
        }

        if (payload_read != flen) {
            ESP_LOGW(TAG, "Incomplete frame read (%d/%u)", payload_read, flen);
            free(frame_data);
            break;
        }

        // Try to decrypt
        if (ftype == 0x04 && flen >= NOISE_MAC_LEN) {
            size_t plain_len = flen - NOISE_MAC_LEN;
            uint8_t *plain = malloc(plain_len + 1);
            if (plain) {
                ESP_LOGI(TAG, "Attempting decrypt with rx_nonce=%lu", (unsigned long)noise.rx_nonce);
                ret = noise_decrypt(noise.rx_key, noise.rx_nonce,
                                   NULL, 0,
                                   frame_data, flen,
                                   plain);
                if (ret == ESP_OK) {
                    plain[plain_len] = '\0';
                    ESP_LOGI(TAG, "Decrypted server frame %d (%u bytes):", frame_attempt, (unsigned int)plain_len);
                    log_hex("Decrypted", plain, plain_len < 64 ? plain_len : 64);

                    // Check for HTTP/2 frames inside
                    if (plain_len >= 9) {
                        uint32_t h2_len = (plain[0] << 16) | (plain[1] << 8) | plain[2];
                        uint8_t h2_type = plain[3];
                        ESP_LOGI(TAG, "  Contains HTTP/2: type=%u, len=%lu", h2_type, (unsigned long)h2_len);
                    }

                    noise.rx_nonce++;
                    server_frames_read++;
                } else {
                    ESP_LOGW(TAG, "Failed to decrypt frame %d with nonce %lu",
                             frame_attempt, (unsigned long)noise.rx_nonce);
                }
                free(plain);
            }
        } else {
            ESP_LOGW(TAG, "Unexpected frame type 0x%02x", ftype);
        }

        free(frame_data);
    }

    // Reset socket to blocking with longer timeout
    struct timeval tv_long;
    tv_long.tv_sec = 5;
    tv_long.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_long, sizeof(tv_long));

    ESP_LOGI(TAG, "Consumed %d server HTTP/2 preface frames, rx_nonce now=%lu",
             server_frames_read, (unsigned long)noise.rx_nonce);

    // First send RegisterRequest to /machine/register, then MapRequest to /machine/map
    // Build HTTP/2 HEADERS frame with POST request
    ESP_LOGI(TAG, "Sending RegisterRequest via HTTP/2 POST to /machine/register...");

    // Build proper RegisterRequest JSON with required fields
    // RegisterRequest needs: Version, NodeKey, Hostinfo, Auth (with AuthKey)
    cJSON *reg_req = cJSON_CreateObject();

    // Version - capability version
    cJSON_AddNumberToObject(reg_req, "Version", TAILSCALE_PROTOCOL_VERSION);

    // NodeKey - our WireGuard public key in "nodekey:hex" format (64 hex chars)
    uint8_t *wg_pubkey = ml->wireguard.public_key;
    char nodekey_hex[65];  // 64 hex chars + null terminator
    for (int i = 0; i < 32; i++) {
        sprintf(&nodekey_hex[i * 2], "%02x", wg_pubkey[i]);
    }
    char nodekey_str[80];
    snprintf(nodekey_str, sizeof(nodekey_str), "nodekey:%s", nodekey_hex);
    cJSON_AddStringToObject(reg_req, "NodeKey", nodekey_str);

    // Hostinfo - device information
    cJSON *hostinfo = cJSON_CreateObject();
    cJSON_AddStringToObject(hostinfo, "Hostname", ml->config.device_name);
    cJSON_AddStringToObject(hostinfo, "OS", "linux");  // ESP32 reports as linux
    cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
    cJSON_AddStringToObject(hostinfo, "GoArch", "arm");  // Closest match
    cJSON_AddItemToObject(reg_req, "Hostinfo", hostinfo);

    // NodeKeyChallengeResponse - prove we own the WireGuard private key (NodeKey)
    // The server sends a challenge public key in EarlyNoise, and we respond with:
    // X25519(wg_private_key, challenge_public_key) - the shared secret proves ownership
    if (g_has_node_key_challenge) {
        ESP_LOGI(TAG, "Computing NodeKeyChallengeResponse...");
        log_hex("  Challenge pubkey", g_node_key_challenge, 32);
        log_hex("  Our WG privkey", ml->wireguard.private_key, 32);

        // Compute X25519 shared secret: response = DH(wg_private, challenge_pub)
        // Per RFC 7748, clear high bit of public key for compatibility
        uint8_t challenge_pub_copy[32];
        memcpy(challenge_pub_copy, g_node_key_challenge, 32);
        challenge_pub_copy[31] &= 0x7F;  // Clear high bit per RFC 7748

        uint8_t challenge_response[32];
        int dh_ret = x25519(challenge_response, ml->wireguard.private_key, challenge_pub_copy, 1);
        if (dh_ret != 0) {
            ESP_LOGW(TAG, "X25519 returned non-zero (non-contributory), proceeding anyway");
        }
        log_hex("  Challenge response", challenge_response, 32);

        // Encode as "chalresp:hex..." format
        char chalresp_hex[65];  // 64 hex chars + null
        for (int i = 0; i < 32; i++) {
            sprintf(&chalresp_hex[i * 2], "%02x", challenge_response[i]);
        }
        char chalresp_str[80];
        snprintf(chalresp_str, sizeof(chalresp_str), "chalresp:%s", chalresp_hex);
        cJSON_AddStringToObject(reg_req, "NodeKeyChallengeResponse", chalresp_str);
        ESP_LOGI(TAG, "Added NodeKeyChallengeResponse: %.40s...", chalresp_str);
    } else {
        ESP_LOGW(TAG, "No nodeKeyChallenge received - registration may fail!");
    }

    // Auth key for registration - nested in Auth.AuthKey structure per Tailscale protocol
    if (ml->config.auth_key && strlen(ml->config.auth_key) > 0) {
        cJSON *auth = cJSON_CreateObject();
        cJSON_AddStringToObject(auth, "AuthKey", ml->config.auth_key);
        cJSON_AddItemToObject(reg_req, "Auth", auth);
    }

    // Convert to string
    char *reg_req_str = cJSON_PrintUnformatted(reg_req);
    cJSON_Delete(reg_req);

    if (!reg_req_str) {
        ESP_LOGE(TAG, "Failed to serialize RegisterRequest");
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    size_t json_payload_len = strlen(reg_req_str);
    ESP_LOGI(TAG, "RegisterRequest payload (%u bytes): %.200s%s",
             (unsigned int)json_payload_len, reg_req_str, json_payload_len > 200 ? "..." : "");

    // Build HTTP/2 HEADERS frame (simplified - no HPACK compression)
    // Frame format: 9-byte header + payload
    // Header: length(3) + type(1) + flags(1) + stream_id(4)

    // For Tailscale registration, we need to send:
    // - HEADERS frame with :method=POST, :path=/machine/register, :authority, content-type
    // - DATA frame with the JSON RegisterRequest payload

    // HPACK encoded headers (minimal, using literal representation)
    // :method: POST (index 3 in static table)
    // :path: /machine/register (literal)
    // :scheme: https (index 7)
    // :authority: controlplane.tailscale.com (literal)
    // content-type: application/json (literal)

    uint8_t hpack_headers[256];
    int hpack_len = 0;

    // :method: POST (indexed, static table index 3)
    hpack_headers[hpack_len++] = 0x83;  // Indexed header field (1 << 7 | 3)

    // :scheme: http (indexed, static table index 6)
    hpack_headers[hpack_len++] = 0x86;  // Indexed header field (1 << 7 | 6)

    // :path: /machine/register (literal with indexing) - for initial registration
    hpack_headers[hpack_len++] = 0x44;  // Literal with indexing, name index 4 (:path)
    const char *path = "/machine/register";
    hpack_headers[hpack_len++] = strlen(path);
    memcpy(hpack_headers + hpack_len, path, strlen(path));
    hpack_len += strlen(path);

    // :authority: controlplane.tailscale.com (literal with indexing)
    hpack_headers[hpack_len++] = 0x41;  // Literal with indexing, name index 1 (:authority)
    const char *authority = TAILSCALE_CONTROL_HOST;
    hpack_headers[hpack_len++] = strlen(authority);
    memcpy(hpack_headers + hpack_len, authority, strlen(authority));
    hpack_len += strlen(authority);

    // content-type: application/json (literal without indexing)
    hpack_headers[hpack_len++] = 0x00;  // Literal without indexing, new name
    const char *ct_name = "content-type";
    hpack_headers[hpack_len++] = strlen(ct_name);
    memcpy(hpack_headers + hpack_len, ct_name, strlen(ct_name));
    hpack_len += strlen(ct_name);
    const char *ct_value = "application/json";
    hpack_headers[hpack_len++] = strlen(ct_value);
    memcpy(hpack_headers + hpack_len, ct_value, strlen(ct_value));
    hpack_len += strlen(ct_value);

    ESP_LOGI(TAG, "HPACK headers (%d bytes):", hpack_len);
    log_hex("HPACK", hpack_headers, hpack_len);

    // Build HEADERS frame
    // Type 0x01 = HEADERS, Flags 0x04 = END_HEADERS, Stream ID = 1
    uint8_t h2_headers_frame[9 + 256];
    h2_headers_frame[0] = (hpack_len >> 16) & 0xFF;
    h2_headers_frame[1] = (hpack_len >> 8) & 0xFF;
    h2_headers_frame[2] = hpack_len & 0xFF;
    h2_headers_frame[3] = 0x01;  // Type: HEADERS
    h2_headers_frame[4] = 0x04;  // Flags: END_HEADERS
    h2_headers_frame[5] = 0x00;  // Stream ID (4 bytes, big-endian)
    h2_headers_frame[6] = 0x00;
    h2_headers_frame[7] = 0x00;
    h2_headers_frame[8] = 0x01;  // Stream ID = 1
    memcpy(h2_headers_frame + 9, hpack_headers, hpack_len);

    size_t headers_frame_len = 9 + hpack_len;

    // Build DATA frame
    // Type 0x00 = DATA, Flags 0x01 = END_STREAM, Stream ID = 1
    uint8_t *h2_data_frame = malloc(9 + json_payload_len);
    if (!h2_data_frame) {
        ESP_LOGE(TAG, "Failed to allocate DATA frame");
        free(reg_req_str);
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    h2_data_frame[0] = (json_payload_len >> 16) & 0xFF;
    h2_data_frame[1] = (json_payload_len >> 8) & 0xFF;
    h2_data_frame[2] = json_payload_len & 0xFF;
    h2_data_frame[3] = 0x00;  // Type: DATA
    h2_data_frame[4] = 0x01;  // Flags: END_STREAM
    h2_data_frame[5] = 0x00;  // Stream ID (4 bytes)
    h2_data_frame[6] = 0x00;
    h2_data_frame[7] = 0x00;
    h2_data_frame[8] = 0x01;  // Stream ID = 1
    memcpy(h2_data_frame + 9, reg_req_str, json_payload_len);
    free(reg_req_str);  // Done with the JSON string
    reg_req_str = NULL;

    size_t data_frame_len = 9 + json_payload_len;

    // Combine HEADERS + DATA into one buffer for encryption
    size_t h2_total_len = headers_frame_len + data_frame_len;
    uint8_t *h2_combined = malloc(h2_total_len);
    if (!h2_combined) {
        free(h2_data_frame);
        ESP_LOGE(TAG, "Failed to allocate combined H2 buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    memcpy(h2_combined, h2_headers_frame, headers_frame_len);
    memcpy(h2_combined + headers_frame_len, h2_data_frame, data_frame_len);
    free(h2_data_frame);

    ESP_LOGI(TAG, "HTTP/2 request (%u bytes): HEADERS(%u) + DATA(%u)",
             (unsigned int)h2_total_len, (unsigned int)headers_frame_len, (unsigned int)data_frame_len);
    log_hex("H2 HEADERS frame", h2_combined, headers_frame_len < 64 ? headers_frame_len : 64);

    // Encrypt and send
    size_t enc_len = h2_total_len + NOISE_MAC_LEN;
    uint8_t *enc_buf = malloc(3 + enc_len);
    if (!enc_buf) {
        free(h2_combined);
        ESP_LOGE(TAG, "Failed to allocate encryption buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    enc_buf[0] = 0x04;  // Noise frame type
    enc_buf[1] = (enc_len >> 8) & 0xFF;
    enc_buf[2] = enc_len & 0xFF;

    ESP_LOGI(TAG, "Encrypting RegisterRequest with tx_nonce=%lu", (unsigned long)noise.tx_nonce);

    ret = noise_encrypt(noise.tx_key, noise.tx_nonce++,
                       NULL, 0,
                       h2_combined, h2_total_len,
                       enc_buf + 3);
    free(h2_combined);

    if (ret != ESP_OK) {
        free(enc_buf);
        ESP_LOGE(TAG, "Failed to encrypt RegisterRequest");
        close(sock);
        goto cleanup;
    }

    int send_len = 3 + enc_len;
    ESP_LOGI(TAG, "Sending encrypted RegisterRequest (%d bytes)", send_len);

    sent = send(sock, enc_buf, send_len, 0);
    free(enc_buf);

    if (sent != send_len) {
        ESP_LOGE(TAG, "Failed to send RegisterRequest: %d (errno: %d)", sent, errno);
        close(sock);
        ret = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(TAG, "RegisterRequest sent, waiting for server response...");

    // HTTP/2 responses may span multiple Noise frames:
    // - First frame: HEADERS (with response status and headers)
    // - Second frame: DATA (with actual JSON body)
    // We need to read and accumulate all frames until we get the complete response

    // Buffer to accumulate decrypted HTTP/2 data
    uint8_t *h2_buffer = malloc(8192);  // Should be enough for RegisterResponse
    if (!h2_buffer) {
        ESP_LOGE(TAG, "Failed to allocate H2 buffer");
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    size_t h2_buffer_len = 0;
    bool got_end_stream = false;

    // Read multiple Noise frames until we get END_STREAM
    for (int frame_count = 0; frame_count < 10 && !got_end_stream; frame_count++) {
        // Read the 3-byte Noise frame header (type + length)
        uint8_t resp_header[3];
        int header_read = 0;
        for (int retry = 0; retry < 30 && header_read < 3; retry++) {
            int n = recv(sock, resp_header + header_read, 3 - header_read, 0);
            if (n > 0) {
                header_read += n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGW(TAG, "Header read error: %d (errno: %d)", n, errno);
                break;
            }
            if (header_read < 3) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }

        if (header_read < 3) {
            if (frame_count == 0) {
                ESP_LOGE(TAG, "Failed to read first response header (got %d/3)", header_read);
                free(h2_buffer);
                close(sock);
                ret = ESP_FAIL;
                goto cleanup;
            }
            ESP_LOGW(TAG, "No more frames available after %d frames", frame_count);
            break;
        }

        uint8_t resp_type = resp_header[0];
        uint16_t resp_payload_len = (resp_header[1] << 8) | resp_header[2];

        ESP_LOGI(TAG, "Response frame %d: type=0x%02x, length=%u, rx_nonce=%lu",
                 frame_count, resp_type, resp_payload_len, (unsigned long)noise.rx_nonce);

        if (resp_type == 0x03) {
            ESP_LOGW(TAG, "Server sent ERROR response (type 0x03)!");
        } else if (resp_type != 0x04) {
            ESP_LOGW(TAG, "Unexpected response type 0x%02x (expected 0x04 Data)", resp_type);
        }

        if (resp_payload_len > 4096) {
            ESP_LOGE(TAG, "Response frame too large: %u bytes", resp_payload_len);
            free(h2_buffer);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }

        // Read encrypted response payload
        uint8_t *resp_encrypted = malloc(resp_payload_len);
        if (!resp_encrypted) {
            ESP_LOGE(TAG, "Failed to allocate response buffer");
            free(h2_buffer);
            close(sock);
            ret = ESP_ERR_NO_MEM;
            goto cleanup;
        }

        int payload_read = 0;
        for (int retry = 0; retry < 30 && payload_read < resp_payload_len; retry++) {
            int n = recv(sock, resp_encrypted + payload_read, resp_payload_len - payload_read, 0);
            if (n > 0) {
                payload_read += n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGW(TAG, "Payload read error: %d (errno: %d)", n, errno);
            }
            if (payload_read < resp_payload_len) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }

        if (payload_read < resp_payload_len) {
            ESP_LOGE(TAG, "Failed to read response payload (got %d/%u)", payload_read, resp_payload_len);
            free(resp_encrypted);
            free(h2_buffer);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }

        // Decrypt this frame
        size_t decrypted_len = resp_payload_len - NOISE_MAC_LEN;
        uint8_t *decrypted_frame = malloc(decrypted_len);
        if (!decrypted_frame) {
            free(resp_encrypted);
            free(h2_buffer);
            close(sock);
            ret = ESP_ERR_NO_MEM;
            goto cleanup;
        }

        ret = noise_decrypt(noise.rx_key, noise.rx_nonce,
                           NULL, 0,
                           resp_encrypted, resp_payload_len,
                           decrypted_frame);
        free(resp_encrypted);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to decrypt frame %d with rx_nonce=%lu",
                     frame_count, (unsigned long)noise.rx_nonce);
            free(decrypted_frame);
            free(h2_buffer);
            close(sock);
            ret = ESP_FAIL;
            goto cleanup;
        }

        noise.rx_nonce++;

        ESP_LOGI(TAG, "Decrypted frame %d (%u bytes)", frame_count, (unsigned int)decrypted_len);
        log_hex("Decrypted", decrypted_frame, decrypted_len < 64 ? decrypted_len : 64);

        // Parse HTTP/2 frame header to check for END_STREAM flag
        if (decrypted_len >= 9) {
            uint8_t h2_flags = decrypted_frame[4];
            uint8_t h2_type = decrypted_frame[3];
            ESP_LOGI(TAG, "  H2 frame type=%u, flags=0x%02x", h2_type, h2_flags);

            // Check END_STREAM flag (0x01) on HEADERS or DATA frames
            if ((h2_type == 0x00 || h2_type == 0x01) && (h2_flags & 0x01)) {
                ESP_LOGI(TAG, "  END_STREAM flag set - this is the last frame");
                got_end_stream = true;
            }
        }

        // Append to buffer
        if (h2_buffer_len + decrypted_len <= 8192) {
            memcpy(h2_buffer + h2_buffer_len, decrypted_frame, decrypted_len);
            h2_buffer_len += decrypted_len;
        } else {
            ESP_LOGW(TAG, "H2 buffer full, truncating");
        }

        free(decrypted_frame);
    }

    ESP_LOGI(TAG, "Accumulated %u bytes of HTTP/2 data", (unsigned int)h2_buffer_len);

    // Now parse all accumulated HTTP/2 frames
    uint8_t *frame_ptr = h2_buffer;
    size_t remaining = h2_buffer_len;
    uint8_t *json_data = NULL;
    size_t json_len = 0;

    while (remaining >= 9) {
        uint32_t frame_len = (frame_ptr[0] << 16) | (frame_ptr[1] << 8) | frame_ptr[2];
        uint8_t frame_type = frame_ptr[3];
        uint8_t frame_flags = frame_ptr[4];
        uint32_t stream_id = ((frame_ptr[5] & 0x7F) << 24) | (frame_ptr[6] << 16) |
                            (frame_ptr[7] << 8) | frame_ptr[8];

        ESP_LOGI(TAG, "HTTP/2 frame: len=%lu, type=%u, flags=0x%02x, stream=%lu",
                 (unsigned long)frame_len, frame_type, frame_flags, (unsigned long)stream_id);

        if (9 + frame_len > remaining) {
            ESP_LOGW(TAG, "Incomplete HTTP/2 frame");
            break;
        }

        if (frame_type == 0x00) {  // DATA frame
            ESP_LOGI(TAG, "Found DATA frame with %lu bytes", (unsigned long)frame_len);
            json_data = frame_ptr + 9;
            json_len = frame_len;
            log_hex("DATA payload", json_data, frame_len < 128 ? frame_len : 128);
        } else if (frame_type == 0x01) {  // HEADERS frame
            ESP_LOGI(TAG, "Found HEADERS frame with %lu bytes", (unsigned long)frame_len);
            log_hex("HEADERS payload", frame_ptr + 9, frame_len < 64 ? frame_len : 64);
        } else if (frame_type == 0x04) {  // SETTINGS frame
            ESP_LOGI(TAG, "Found SETTINGS frame");
        } else if (frame_type == 0x07) {  // GOAWAY frame
            ESP_LOGW(TAG, "Server sent GOAWAY!");
            if (frame_len >= 8) {
                uint32_t last_stream = ((frame_ptr[9] & 0x7F) << 24) | (frame_ptr[10] << 16) |
                                      (frame_ptr[11] << 8) | frame_ptr[12];
                uint32_t error_code = (frame_ptr[13] << 24) | (frame_ptr[14] << 16) |
                                     (frame_ptr[15] << 8) | frame_ptr[16];
                ESP_LOGW(TAG, "GOAWAY: last_stream=%lu, error=%lu",
                         (unsigned long)last_stream, (unsigned long)error_code);
            }
        } else if (frame_type == 0x03) {  // RST_STREAM
            ESP_LOGW(TAG, "Server sent RST_STREAM");
        }

        frame_ptr += 9 + frame_len;
        remaining -= 9 + frame_len;
    }

    // If no DATA frame found, treat the whole response as potential JSON
    if (!json_data && h2_buffer_len > 0) {
        // Maybe it's raw JSON?
        json_data = h2_buffer;
        json_len = h2_buffer_len;
    }

    if (!json_data || json_len == 0) {
        ESP_LOGW(TAG, "No JSON data found in response");
        free(h2_buffer);
        close(sock);
        ret = ESP_OK;  // Not an error, just no data yet
        goto cleanup;
    }

    // Null-terminate for JSON parsing
    uint8_t *json_copy = malloc(json_len + 1);
    if (!json_copy) {
        free(h2_buffer);
        close(sock);
        ret = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    memcpy(json_copy, json_data, json_len);
    json_copy[json_len] = '\0';

    ESP_LOGI(TAG, "Parsing JSON (%u bytes): %.200s%s",
             (unsigned int)json_len, (char *)json_copy, json_len > 200 ? "..." : "");

    // Parse JSON response (Tailscale RegisterResponse)
    // RegisterResponse contains: User, Login, MachineAuthorized, AuthURL, Error, etc.
    // It does NOT contain Node/Addresses - those come from MapResponse
    cJSON *root = cJSON_Parse((const char *)json_copy);
    free(json_copy);
    if (!root) {
        ESP_LOGE(TAG, "Failed to parse JSON response");
        free(h2_buffer);
        goto cleanup;
    }

    // Check for error in registration response
    cJSON *error = cJSON_GetObjectItem(root, "Error");
    if (error && cJSON_IsString(error) && strlen(error->valuestring) > 0) {
        ESP_LOGE(TAG, "Registration error: %s", error->valuestring);
        cJSON_Delete(root);
        free(h2_buffer);
        goto cleanup;
    }

    // Check if machine needs authorization
    cJSON *auth_url = cJSON_GetObjectItem(root, "AuthURL");
    if (auth_url && cJSON_IsString(auth_url) && strlen(auth_url->valuestring) > 0) {
        ESP_LOGW(TAG, "Device needs authorization! Visit: %s", auth_url->valuestring);
        // For pre-auth keys, this shouldn't happen
    }

    // Check machine authorization status
    cJSON *machine_auth = cJSON_GetObjectItem(root, "MachineAuthorized");
    if (machine_auth && cJSON_IsBool(machine_auth)) {
        bool is_authorized = cJSON_IsTrue(machine_auth);
        ESP_LOGI(TAG, "Machine authorized: %s", is_authorized ? "YES" : "NO");
    }

    // Extract user information
    cJSON *user = cJSON_GetObjectItem(root, "User");
    if (user) {
        cJSON *display_name = cJSON_GetObjectItem(user, "DisplayName");
        if (display_name && cJSON_IsString(display_name)) {
            ESP_LOGI(TAG, "Registered as user: %s", display_name->valuestring);
        }
        cJSON *user_id = cJSON_GetObjectItem(user, "ID");
        if (user_id && cJSON_IsNumber(user_id)) {
            ESP_LOGI(TAG, "User ID: %ld", (long)user_id->valuedouble);
        }
    }

    // Extract login information
    cJSON *login = cJSON_GetObjectItem(root, "Login");
    if (login) {
        cJSON *login_name = cJSON_GetObjectItem(login, "LoginName");
        if (login_name && cJSON_IsString(login_name)) {
            ESP_LOGI(TAG, "Login: %s", login_name->valuestring);
        }
    }

    cJSON_Delete(root);
    free(h2_buffer);

    // Store transport keys for future messages (will be used for MapRequest)
    memcpy(ml->coordination.tx_key, noise.tx_key, NOISE_KEY_LEN);
    memcpy(ml->coordination.rx_key, noise.rx_key, NOISE_KEY_LEN);
    ml->coordination.tx_nonce = noise.tx_nonce;
    ml->coordination.rx_nonce = noise.rx_nonce;
    ml->coordination.handshake_complete = true;
    ml->coordination.socket = sock;  // Keep socket open for MapRequest
    ml->coordination.registered = true;
    ml->coordination.next_stream_id = 3;  // Stream 1 was used for register, next is 3

    ESP_LOGI(TAG, "Registration successful! Device registered with Tailscale.");
    ESP_LOGI(TAG, "Socket stored for MapRequest, tx_nonce=%lu, rx_nonce=%lu, next_stream=%lu",
             (unsigned long)ml->coordination.tx_nonce,
             (unsigned long)ml->coordination.rx_nonce,
             (unsigned long)ml->coordination.next_stream_id);

    // NOTE: VPN IP comes from MapResponse, not RegisterResponse
    // The state machine will call microlink_coordination_fetch_peers() next
    // which should send a MapRequest to /machine/map

    ret = ESP_OK;  // Registration success!
    sock = -1;  // Don't close on success - socket ownership transferred to ml->coordination

cleanup:
    // Clean up socket connection (only on error)
    // Note: On success, we should keep the socket open for future Noise-encrypted communication
    // For now we'll close it since ongoing connection handling isn't implemented yet
    if (sock >= 0 && ret != ESP_OK) {
        close(sock);
    }

    // Free allocated buffers
    if (msg1) free(msg1);
    if (msg2) free(msg2);
    if (response_payload) free(response_payload);
    if (payload) free(payload);

    return ret;
}

esp_err_t microlink_coordination_fetch_peers(microlink_t *ml) {
    ESP_LOGI(TAG, "Fetching peer list via MapRequest");

    // Check if we have a valid socket from registration
    if (ml->coordination.socket < 0 || !ml->coordination.registered) {
        ESP_LOGE(TAG, "No valid socket - need to re-register first");
        return ESP_ERR_INVALID_STATE;
    }

    int sock = ml->coordination.socket;
    esp_err_t ret = ESP_FAIL;

    // Check for any pending data from server (might be GOAWAY or other frames)
    uint8_t peek_buf[256];
    struct timeval peek_tv = { .tv_sec = 0, .tv_usec = 100000 };  // 100ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &peek_tv, sizeof(peek_tv));
    int peek_len = recv(sock, peek_buf, sizeof(peek_buf), MSG_PEEK);
    if (peek_len > 0) {
        ESP_LOGW(TAG, "Server has %d pending bytes before MapRequest!", peek_len);
        ESP_LOGW(TAG, "Pending data: %02x %02x %02x %02x %02x %02x %02x %02x",
                 peek_buf[0], peek_buf[1], peek_buf[2], peek_buf[3],
                 peek_buf[4], peek_buf[5], peek_buf[6], peek_buf[7]);

        // Drain and process the pending data - it might contain important frames
        recv(sock, peek_buf, peek_len, 0);

        // Check if it's a Noise transport frame (type 0x04)
        if (peek_buf[0] == 0x04) {
            uint16_t frame_len = (peek_buf[1] << 8) | peek_buf[2];
            ESP_LOGW(TAG, "Pending Noise frame: type=0x%02x, len=%u", peek_buf[0], frame_len);

            // Try to decrypt and see what HTTP/2 frame is inside
            if (frame_len > 16 && peek_len >= 3 + frame_len) {
                uint8_t decrypted[256];
                esp_err_t dec_ret = noise_decrypt(ml->coordination.rx_key, ml->coordination.rx_nonce,
                                                  NULL, 0, peek_buf + 3, frame_len, decrypted);
                if (dec_ret == ESP_OK) {
                    ml->coordination.rx_nonce++;
                    size_t dec_len = frame_len - 16;
                    if (dec_len >= 9) {
                        uint32_t h2_len = (decrypted[0] << 16) | (decrypted[1] << 8) | decrypted[2];
                        uint8_t h2_type = decrypted[3];
                        ESP_LOGW(TAG, "Pending HTTP/2 frame: type=%u, len=%lu", h2_type, (unsigned long)h2_len);
                        if (h2_type == 7) {
                            ESP_LOGE(TAG, "*** Server sent GOAWAY - connection is being terminated! ***");
                            ml->coordination.socket = -1;
                            ml->coordination.goaway_received = true;
                            return ESP_ERR_INVALID_STATE;
                        }
                    }
                }
            }
        }
    } else if (peek_len == 0) {
        ESP_LOGE(TAG, "Server closed connection before MapRequest!");
        ml->coordination.socket = -1;
        return ESP_ERR_INVALID_STATE;
    } else {
        // peek_len < 0: EAGAIN or error - no pending data, which is normal
        ESP_LOGI(TAG, "No pending server data before MapRequest (good)");
    }

    // Build MapRequest JSON
    cJSON *map_req = cJSON_CreateObject();
    cJSON_AddNumberToObject(map_req, "Version", TAILSCALE_PROTOCOL_VERSION);

    // NodeKey in hex format
    uint8_t *wg_pubkey = ml->wireguard.public_key;
    char nodekey_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&nodekey_hex[i * 2], "%02x", wg_pubkey[i]);
    }
    char nodekey_str[80];
    snprintf(nodekey_str, sizeof(nodekey_str), "nodekey:%s", nodekey_hex);
    cJSON_AddStringToObject(map_req, "NodeKey", nodekey_str);

    // DiscoKey in hex format
    uint8_t *disco_pubkey = ml->wireguard.disco_public_key;
    char discokey_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(&discokey_hex[i * 2], "%02x", disco_pubkey[i]);
    }
    char discokey_str[80];
    snprintf(discokey_str, sizeof(discokey_str), "discokey:%s", discokey_hex);
    cJSON_AddStringToObject(map_req, "DiscoKey", discokey_str);

    // Hostinfo
    cJSON *hostinfo = cJSON_CreateObject();
    cJSON_AddStringToObject(hostinfo, "Hostname", ml->config.device_name);
    cJSON_AddStringToObject(hostinfo, "OS", "linux");
    cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
    cJSON_AddStringToObject(hostinfo, "GoArch", "arm");

    // NetInfo contains network capability information including DERP home region
    // PreferredDERP tells the control plane which DERP server we're using
    // This is CRITICAL - without it, other peers don't know how to reach us via DERP!
    cJSON *netinfo = cJSON_CreateObject();
    cJSON_AddNumberToObject(netinfo, "PreferredDERP", MICROLINK_DERP_REGION);  // Must match DERP server!
    cJSON_AddBoolToObject(netinfo, "WorkingUDP", true);     // We support UDP
    cJSON_AddBoolToObject(netinfo, "WorkingIPv6", false);   // ESP32 doesn't have IPv6 here
    cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);
    ESP_LOGI(TAG, "NetInfo.PreferredDERP: %d (Dallas)", MICROLINK_DERP_REGION);

    cJSON_AddItemToObject(map_req, "Hostinfo", hostinfo);

    // Endpoints - both local and STUN-discovered addresses
    // This tells other peers where to reach us directly
    // Type 1 = EndpointLocal (local network address)
    // Type 2 = EndpointSTUN (discovered via STUN - NAT-traversal)
    {
        cJSON *endpoints = cJSON_CreateArray();
        cJSON *endpoint_types = cJSON_CreateArray();
        int endpoint_count = 0;

        // Add local WiFi endpoint (EndpointLocal = 1)
        // This allows peers on the same LAN to connect directly
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        esp_netif_ip_info_t ip_info;
        if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            char local_ep[32];
            snprintf(local_ep, sizeof(local_ep), "%d.%d.%d.%d:%u",
                     (ip_info.ip.addr) & 0xFF,
                     (ip_info.ip.addr >> 8) & 0xFF,
                     (ip_info.ip.addr >> 16) & 0xFF,
                     (ip_info.ip.addr >> 24) & 0xFF,
                     ml->wireguard.listen_port);
            cJSON_AddItemToArray(endpoints, cJSON_CreateString(local_ep));
            cJSON_AddItemToArray(endpoint_types, cJSON_CreateNumber(1));  // EndpointLocal
            endpoint_count++;
            ESP_LOGI(TAG, "Advertising local endpoint: %s (type: Local)", local_ep);
        }

        // Add STUN endpoint (EndpointSTUN = 2) if available
        if (ml->stun.public_ip != 0 && ml->stun.public_port != 0) {
            char stun_ep[32];
            snprintf(stun_ep, sizeof(stun_ep), "%lu.%lu.%lu.%lu:%u",
                     (unsigned long)((ml->stun.public_ip >> 24) & 0xFF),
                     (unsigned long)((ml->stun.public_ip >> 16) & 0xFF),
                     (unsigned long)((ml->stun.public_ip >> 8) & 0xFF),
                     (unsigned long)(ml->stun.public_ip & 0xFF),
                     ml->stun.public_port);
            cJSON_AddItemToArray(endpoints, cJSON_CreateString(stun_ep));
            cJSON_AddItemToArray(endpoint_types, cJSON_CreateNumber(2));  // EndpointSTUN
            endpoint_count++;
            ESP_LOGI(TAG, "Advertising STUN endpoint: %s (type: STUN)", stun_ep);
        }

        if (endpoint_count > 0) {
            cJSON_AddItemToObject(map_req, "Endpoints", endpoints);
            cJSON_AddItemToObject(map_req, "EndpointTypes", endpoint_types);
        } else {
            cJSON_Delete(endpoints);
            cJSON_Delete(endpoint_types);
            ESP_LOGW(TAG, "No endpoints discovered - peers can only reach us via DERP");
        }
    }

    // NOTE: DERP home region is communicated via Hostinfo.NetInfo.PreferredDERP (above)
    // NOT via a top-level DERPRegion field (that was a protocol misunderstanding)

    // CRITICAL: For the FIRST request, use Stream=false to ensure Hostinfo is processed!
    // Per Tailscale protocol (capver >= 68), Stream=true causes server to IGNORE:
    //   - Hostinfo (including NetInfo.PreferredDERP!)
    //   - Endpoints
    // We send Stream=false first to set up our identity, then Stream=true for long-poll.
    //
    // NOTE: We're using the same HTTP/2 connection but different stream IDs.
    // After getting the initial response on this stream, we'll open a new stream
    // with Stream=true for long-poll.
    cJSON_AddBoolToObject(map_req, "Stream", false);  // First request: non-streaming to set DERPRegion!
    cJSON_AddStringToObject(map_req, "Compress", "");  // Disable compression - empty string means no compression

    // Note: Removed OmitPeers - we need full response to get Node.Addresses with VPN IP
    // The response may be large (includes DERP map) but contains our assigned IP

    char *map_req_str = cJSON_PrintUnformatted(map_req);
    cJSON_Delete(map_req);

    if (!map_req_str) {
        ESP_LOGE(TAG, "Failed to serialize MapRequest");
        return ESP_ERR_NO_MEM;
    }

    size_t json_len = strlen(map_req_str);
    ESP_LOGI(TAG, "MapRequest (%u bytes): %.150s%s", (unsigned int)json_len, map_req_str, json_len > 150 ? "..." : "");

    // Build HPACK headers for /machine/map
    uint8_t hpack_headers[256];
    int hpack_len = 0;

    hpack_headers[hpack_len++] = 0x83;  // :method: POST
    hpack_headers[hpack_len++] = 0x86;  // :scheme: http

    // :path: /machine/map
    hpack_headers[hpack_len++] = 0x44;
    const char *path = "/machine/map";
    hpack_headers[hpack_len++] = strlen(path);
    memcpy(hpack_headers + hpack_len, path, strlen(path));
    hpack_len += strlen(path);

    // :authority: controlplane.tailscale.com
    hpack_headers[hpack_len++] = 0x41;
    const char *authority = TAILSCALE_CONTROL_HOST;
    hpack_headers[hpack_len++] = strlen(authority);
    memcpy(hpack_headers + hpack_len, authority, strlen(authority));
    hpack_len += strlen(authority);

    // content-type: application/json
    hpack_headers[hpack_len++] = 0x00;
    const char *ct_name = "content-type";
    hpack_headers[hpack_len++] = strlen(ct_name);
    memcpy(hpack_headers + hpack_len, ct_name, strlen(ct_name));
    hpack_len += strlen(ct_name);
    const char *ct_value = "application/json";
    hpack_headers[hpack_len++] = strlen(ct_value);
    memcpy(hpack_headers + hpack_len, ct_value, strlen(ct_value));
    hpack_len += strlen(ct_value);

    // Get next stream ID and increment for next request
    // HTTP/2 client-initiated streams use odd numbers: 1, 3, 5, 7, ...
    uint32_t stream_id = ml->coordination.next_stream_id;
    ml->coordination.next_stream_id += 2;  // Next will be 5, 7, 9, etc.
    ESP_LOGI(TAG, "Using HTTP/2 stream ID %lu for MapRequest", (unsigned long)stream_id);

    // Build HTTP/2 HEADERS frame
    uint8_t h2_headers_frame[9 + 256];
    h2_headers_frame[0] = (hpack_len >> 16) & 0xFF;
    h2_headers_frame[1] = (hpack_len >> 8) & 0xFF;
    h2_headers_frame[2] = hpack_len & 0xFF;
    h2_headers_frame[3] = 0x01;  // HEADERS
    h2_headers_frame[4] = 0x04;  // END_HEADERS
    h2_headers_frame[5] = (stream_id >> 24) & 0x7F;  // Mask high bit (reserved)
    h2_headers_frame[6] = (stream_id >> 16) & 0xFF;
    h2_headers_frame[7] = (stream_id >> 8) & 0xFF;
    h2_headers_frame[8] = stream_id & 0xFF;
    memcpy(h2_headers_frame + 9, hpack_headers, hpack_len);
    int headers_frame_len = 9 + hpack_len;

    // Build HTTP/2 DATA frame
    uint8_t *h2_data_frame = malloc(9 + json_len);
    if (!h2_data_frame) {
        free(map_req_str);
        return ESP_ERR_NO_MEM;
    }

    h2_data_frame[0] = (json_len >> 16) & 0xFF;
    h2_data_frame[1] = (json_len >> 8) & 0xFF;
    h2_data_frame[2] = json_len & 0xFF;
    h2_data_frame[3] = 0x00;  // DATA
    h2_data_frame[4] = 0x01;  // END_STREAM
    h2_data_frame[5] = (stream_id >> 24) & 0x7F;
    h2_data_frame[6] = (stream_id >> 16) & 0xFF;
    h2_data_frame[7] = (stream_id >> 8) & 0xFF;
    h2_data_frame[8] = stream_id & 0xFF;
    memcpy(h2_data_frame + 9, map_req_str, json_len);
    int data_frame_len = 9 + json_len;

    free(map_req_str);

    // Combine frames
    int h2_total_len = headers_frame_len + data_frame_len;
    uint8_t *h2_combined = malloc(h2_total_len);
    if (!h2_combined) {
        free(h2_data_frame);
        return ESP_ERR_NO_MEM;
    }

    memcpy(h2_combined, h2_headers_frame, headers_frame_len);
    memcpy(h2_combined + headers_frame_len, h2_data_frame, data_frame_len);
    free(h2_data_frame);

    // Encrypt with transport keys
    int enc_len = h2_total_len + 16;  // + MAC
    uint8_t *enc_buf = malloc(3 + enc_len);
    if (!enc_buf) {
        free(h2_combined);
        return ESP_ERR_NO_MEM;
    }

    enc_buf[0] = 0x04;  // Noise transport frame
    enc_buf[1] = (enc_len >> 8) & 0xFF;
    enc_buf[2] = enc_len & 0xFF;

    ESP_LOGI(TAG, "Encrypting MapRequest with tx_nonce=%lu", (unsigned long)ml->coordination.tx_nonce);

    ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                        NULL, 0, h2_combined, h2_total_len, enc_buf + 3);
    free(h2_combined);

    if (ret != ESP_OK) {
        free(enc_buf);
        ESP_LOGE(TAG, "Failed to encrypt MapRequest");
        return ret;
    }

    // Send
    int send_len = 3 + enc_len;
    ESP_LOGI(TAG, "Sending MapRequest: %d bytes (Noise frame: type=0x%02x, len=%d), sock=%d",
             send_len, enc_buf[0], enc_len, sock);
    ESP_LOGI(TAG, "  First 16 bytes: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
             enc_buf[0], enc_buf[1], enc_buf[2], enc_buf[3],
             enc_buf[4], enc_buf[5], enc_buf[6], enc_buf[7],
             enc_buf[8], enc_buf[9], enc_buf[10], enc_buf[11],
             enc_buf[12], enc_buf[13], enc_buf[14], enc_buf[15]);
    int sent = send(sock, enc_buf, send_len, 0);
    free(enc_buf);

    if (sent != send_len) {
        ESP_LOGE(TAG, "Failed to send MapRequest: sent=%d, expected=%d, errno=%d", sent, send_len, errno);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "MapRequest sent successfully (%d bytes), waiting for MapResponse...", sent);

    // Check socket health before waiting
    int sock_error = 0;
    socklen_t sock_errlen = sizeof(sock_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &sock_errlen);
    if (sock_error != 0) {
        ESP_LOGE(TAG, "Socket has error before recv: %d", sock_error);
    }

    // Try a quick non-blocking read to see if there's immediate response or error
    struct timeval quick_tv = { .tv_sec = 2, .tv_usec = 0 };  // 2 second quick check
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &quick_tv, sizeof(quick_tv));
    uint8_t quick_peek[64];
    int quick_len = recv(sock, quick_peek, sizeof(quick_peek), MSG_PEEK);
    if (quick_len > 0) {
        ESP_LOGI(TAG, "Quick peek: %d bytes available, type=0x%02x len=%d",
                 quick_len, quick_peek[0],
                 quick_len >= 3 ? ((quick_peek[1] << 8) | quick_peek[2]) : 0);
    } else if (quick_len == 0) {
        ESP_LOGW(TAG, "Server closed connection!");
    } else {
        ESP_LOGW(TAG, "No immediate response (errno=%d)", errno);
    }

    // Set timeout for receiving - 10 seconds for initial response
    // With Stream=true, server should still send initial MapResponse immediately
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Buffer to accumulate all HTTP/2 frames from multiple Noise frames
    uint8_t *h2_buffer = malloc(32768);  // 32KB for HTTP/2 data
    if (!h2_buffer) {
        return ESP_ERR_NO_MEM;
    }
    size_t h2_buffer_len = 0;

    // TCP stream buffer - handles Noise frames that span multiple TCP segments
    uint8_t *tcp_buffer = malloc(32768);  // 32KB for TCP stream reassembly
    if (!tcp_buffer) {
        free(h2_buffer);
        return ESP_ERR_NO_MEM;
    }
    size_t tcp_buffer_len = 0;

    int max_recv_calls = 30;
    bool got_end_stream = false;
    bool got_any_data = false;  // Track if we received any data at all

    for (int recv_idx = 0; recv_idx < max_recv_calls && !got_end_stream; recv_idx++) {
        // Receive into remaining space in tcp_buffer
        size_t space = 32768 - tcp_buffer_len;
        if (space == 0) {
            ESP_LOGE(TAG, "TCP buffer full!");
            break;
        }

        int recv_len = recv(sock, tcp_buffer + tcp_buffer_len, space, 0);
        if (recv_len <= 0) {
            if (!got_any_data) {
                // No data received at all - this is a real error
                ESP_LOGE(TAG, "Failed to receive MapResponse: %d (errno=%d)", recv_len, errno);
                // Check if socket is still valid
                int error = 0;
                socklen_t errlen = sizeof(error);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &errlen);
                if (error != 0) {
                    ESP_LOGE(TAG, "Socket error: %d", error);
                }
                free(tcp_buffer);
                free(h2_buffer);
                return ESP_FAIL;
            }
            // Got some data before timeout - that's OK for Stream=true mode
            // In long-poll, the server may not send END_STREAM until connection closes
            ESP_LOGI(TAG, "Recv timeout after %d calls with %u bytes, processing...",
                     recv_idx, (unsigned int)h2_buffer_len);
            break;
        }

        got_any_data = true;

        tcp_buffer_len += recv_len;
        ESP_LOGD(TAG, "Recv %d: +%d bytes (tcp_buffer=%u)", recv_idx + 1, recv_len, (unsigned int)tcp_buffer_len);

        // Process complete Noise frames from tcp_buffer
        size_t consumed = 0;
        while (consumed + 3 <= tcp_buffer_len) {
            // Check frame type
            if (tcp_buffer[consumed] != 0x04) {
                ESP_LOGE(TAG, "Invalid Noise frame type 0x%02x at offset %u", tcp_buffer[consumed], (unsigned int)consumed);
                // Dump some context for debugging
                ESP_LOGE(TAG, "Context: %02x %02x %02x %02x %02x",
                         tcp_buffer[consumed], tcp_buffer[consumed+1], tcp_buffer[consumed+2],
                         consumed+3 < tcp_buffer_len ? tcp_buffer[consumed+3] : 0,
                         consumed+4 < tcp_buffer_len ? tcp_buffer[consumed+4] : 0);
                got_end_stream = true;  // Stop processing on error
                break;
            }

            // Get frame length
            int payload_len = (tcp_buffer[consumed + 1] << 8) | tcp_buffer[consumed + 2];
            size_t frame_total = 3 + payload_len;

            // Check if we have the complete frame
            if (consumed + frame_total > tcp_buffer_len) {
                // Incomplete frame - wait for more data
                ESP_LOGD(TAG, "Partial frame: have %u, need %u", (unsigned int)(tcp_buffer_len - consumed), (unsigned int)frame_total);
                break;
            }

            // Decrypt this complete Noise frame
            size_t decrypted_len = payload_len - 16;  // Minus MAC
            uint8_t *decrypted = malloc(decrypted_len);
            if (!decrypted) {
                free(tcp_buffer);
                free(h2_buffer);
                return ESP_ERR_NO_MEM;
            }

            ret = noise_decrypt(ml->coordination.rx_key, ml->coordination.rx_nonce++,
                                NULL, 0, tcp_buffer + consumed + 3, payload_len, decrypted);

            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "Failed to decrypt Noise frame (nonce=%lu)",
                         (unsigned long)(ml->coordination.rx_nonce - 1));
                free(decrypted);
                free(tcp_buffer);
                free(h2_buffer);
                return ret;
            }

            // Check HTTP/2 frame header for DATA frames
            // In long-poll mode (Stream=true), END_STREAM won't come until connection closes
            // We just need to detect when we've received a complete initial response
            if (decrypted_len >= 9) {
                int h2_frame_type = decrypted[3];
                int h2_frame_flags = decrypted[4];

                if (h2_frame_type == 0x00) {  // DATA frame
                    // In Stream=true mode, we won't get END_STREAM on first response
                    // Instead, we'll timeout after receiving data - that's OK
                    if (h2_frame_flags & 0x01) {
                        got_end_stream = true;
                        ESP_LOGI(TAG, "Got DATA frame with END_STREAM");
                    } else {
                        ESP_LOGD(TAG, "Got DATA frame (no END_STREAM - long-poll mode)");
                    }
                }
            }

            // Append to h2_buffer
            if (h2_buffer_len + decrypted_len <= 32768) {
                memcpy(h2_buffer + h2_buffer_len, decrypted, decrypted_len);
                h2_buffer_len += decrypted_len;
            }

            free(decrypted);
            consumed += frame_total;
        }

        // Move unconsumed data to beginning of buffer
        if (consumed > 0 && consumed < tcp_buffer_len) {
            memmove(tcp_buffer, tcp_buffer + consumed, tcp_buffer_len - consumed);
            tcp_buffer_len -= consumed;
        } else if (consumed == tcp_buffer_len) {
            tcp_buffer_len = 0;
        }
    }

    free(tcp_buffer);
    ESP_LOGI(TAG, "Received complete response: %u bytes of HTTP/2 data", (unsigned int)h2_buffer_len);

    ESP_LOGI(TAG, "Total HTTP/2 data accumulated: %u bytes", (unsigned int)h2_buffer_len);

    // Accumulate ALL DATA frame payloads into a single JSON buffer
    // MapResponse can be large (includes all DERP region info)
    uint8_t *json_buffer = malloc(65536);  // 64KB for full MapResponse
    if (!json_buffer) {
        free(h2_buffer);
        return ESP_ERR_NO_MEM;
    }
    size_t json_total_len = 0;

    // Parse HTTP/2 frames and accumulate DATA payloads
    size_t pos = 0;
    while (pos + 9 <= h2_buffer_len) {
        int frame_len = (h2_buffer[pos] << 16) | (h2_buffer[pos + 1] << 8) | h2_buffer[pos + 2];
        int frame_type = h2_buffer[pos + 3];
        int frame_flags = h2_buffer[pos + 4];
        int stream_id = (h2_buffer[pos + 5] << 24) | (h2_buffer[pos + 6] << 16) |
                        (h2_buffer[pos + 7] << 8) | h2_buffer[pos + 8];

        // Log each frame type for debugging
        const char *type_name =
            frame_type == 0x00 ? "DATA" :
            frame_type == 0x01 ? "HEADERS" :
            frame_type == 0x02 ? "PRIORITY" :
            frame_type == 0x03 ? "RST_STREAM" :
            frame_type == 0x04 ? "SETTINGS" :
            frame_type == 0x05 ? "PUSH_PROMISE" :
            frame_type == 0x06 ? "PING" :
            frame_type == 0x07 ? "GOAWAY" :
            frame_type == 0x08 ? "WINDOW_UPDATE" :
            frame_type == 0x09 ? "CONTINUATION" : "UNKNOWN";
        ESP_LOGI(TAG, "H2 frame: type=%s(0x%02x), len=%d, flags=0x%02x, stream=%d",
                 type_name, frame_type, frame_len, frame_flags, stream_id);

        // For HEADERS frame, try to decode HTTP status from HPACK
        if (frame_type == 0x01 && frame_len > 0) {
            uint8_t hpack_byte = h2_buffer[pos + 9];
            const char *status =
                hpack_byte == 0x88 ? "200 OK" :
                hpack_byte == 0x89 ? "204 No Content" :
                hpack_byte == 0x8a ? "206 Partial" :
                hpack_byte == 0x8b ? "304 Not Modified" :
                hpack_byte == 0x8c ? "400 Bad Request" :
                hpack_byte == 0x8d ? "404 Not Found" :
                hpack_byte == 0x8e ? "500 Internal Error" : "unknown";
            ESP_LOGI(TAG, "  HEADERS status: %s (HPACK byte 0x%02x)", status, hpack_byte);

            // Log raw HPACK for debugging
            if (frame_len > 1) {
                ESP_LOGI(TAG, "  HPACK bytes: %02x %02x %02x %02x %02x...",
                         h2_buffer[pos + 9],
                         frame_len > 1 ? h2_buffer[pos + 10] : 0,
                         frame_len > 2 ? h2_buffer[pos + 11] : 0,
                         frame_len > 3 ? h2_buffer[pos + 12] : 0,
                         frame_len > 4 ? h2_buffer[pos + 13] : 0);
            }
        }

        // For RST_STREAM or GOAWAY, decode error code
        if (frame_type == 0x03 && frame_len >= 4) {  // RST_STREAM
            uint32_t error_code = (h2_buffer[pos + 9] << 24) | (h2_buffer[pos + 10] << 16) |
                                  (h2_buffer[pos + 11] << 8) | h2_buffer[pos + 12];
            ESP_LOGW(TAG, "  RST_STREAM error code: 0x%08x", error_code);
        }
        if (frame_type == 0x07 && frame_len >= 8) {  // GOAWAY
            uint32_t last_stream = (h2_buffer[pos + 9] << 24) | (h2_buffer[pos + 10] << 16) |
                                   (h2_buffer[pos + 11] << 8) | h2_buffer[pos + 12];
            uint32_t error_code = (h2_buffer[pos + 13] << 24) | (h2_buffer[pos + 14] << 16) |
                                  (h2_buffer[pos + 15] << 8) | h2_buffer[pos + 16];
            ESP_LOGW(TAG, "  GOAWAY: last_stream=%d, error=0x%08x", last_stream, error_code);
            // Mark that we need to reconnect
            ml->coordination.goaway_received = true;
            ESP_LOGI(TAG, "GOAWAY received - will reconnect on next poll");
        }

        if (frame_type == 0x00 && frame_len > 0) {  // DATA frame
            // Append to json_buffer
            if (json_total_len + frame_len <= 65536) {
                memcpy(json_buffer + json_total_len, h2_buffer + pos + 9, frame_len);
                json_total_len += frame_len;
                ESP_LOGD(TAG, "Accumulated DATA frame: %d bytes (total: %u)", frame_len, (unsigned int)json_total_len);
            }
        }

        pos += 9 + frame_len;
    }

    if (json_total_len == 0) {
        ESP_LOGW(TAG, "No DATA frames found in response");
        // Log the raw H2 buffer to see what we got (likely HEADERS with error status)
        if (h2_buffer_len > 0) {
            ESP_LOGW(TAG, "H2 buffer (%u bytes): %02x %02x %02x %02x %02x %02x %02x %02x...",
                     (unsigned int)h2_buffer_len,
                     h2_buffer[0], h2_buffer[1], h2_buffer[2], h2_buffer[3],
                     h2_buffer[4], h2_buffer[5], h2_buffer[6], h2_buffer[7]);
            // Check if first frame is HEADERS (type 0x01)
            if (h2_buffer_len >= 9 && h2_buffer[3] == 0x01) {
                int hdr_len = (h2_buffer[0] << 16) | (h2_buffer[1] << 8) | h2_buffer[2];
                ESP_LOGW(TAG, "HEADERS frame: len=%d, flags=0x%02x", hdr_len, h2_buffer[4]);
                // First byte of HPACK payload often indicates status
                // 0x88 = :status 200, 0x89 = :status 204, etc.
                if (h2_buffer_len > 9) {
                    uint8_t status_byte = h2_buffer[9];
                    ESP_LOGW(TAG, "HPACK first byte: 0x%02x (%s)",
                             status_byte,
                             status_byte == 0x88 ? ":status 200" :
                             status_byte == 0x89 ? ":status 204" :
                             status_byte == 0x8a ? ":status 206" :
                             status_byte == 0x8b ? ":status 304" :
                             status_byte == 0x8c ? ":status 400" :
                             status_byte == 0x8d ? ":status 404" :
                             status_byte == 0x8e ? ":status 500" : "other");
                }
            }
        }
        free(json_buffer);
        free(h2_buffer);
        ml->coordination.last_map_poll_ms = microlink_get_time_ms();
        return ESP_OK;
    }

    free(h2_buffer);

    // Log first bytes to identify compression/encoding
    ESP_LOGI(TAG, "MapResponse first 32 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             json_buffer[0], json_buffer[1], json_buffer[2], json_buffer[3],
             json_buffer[4], json_buffer[5], json_buffer[6], json_buffer[7],
             json_buffer[8], json_buffer[9], json_buffer[10], json_buffer[11],
             json_buffer[12], json_buffer[13], json_buffer[14], json_buffer[15]);

    // Check for zstd magic (28 b5 2f fd)
    bool is_zstd = (json_buffer[0] == 0x28 && json_buffer[1] == 0xb5 &&
                    json_buffer[2] == 0x2f && json_buffer[3] == 0xfd);

    // Check for gzip magic (1f 8b)
    bool is_gzip = (json_buffer[0] == 0x1f && json_buffer[1] == 0x8b);

    // Check for 4-byte length prefix followed by JSON FIRST (Tailscale binary framing)
    // Format: 4-byte length prefix + JSON payload
    // IMPORTANT: Check this BEFORE plain JSON because the first byte of the length
    // could coincidentally be '{' (0x7b), which would falsely trigger plain JSON detection
    // Example: length 31585 = 0x7b61 starts with 0x7b = '{'
    bool is_length_prefixed = (!is_zstd && !is_gzip &&
                               json_total_len > 4 && json_buffer[4] == '{');

    // Check if it starts with '{' (plain JSON) - only if not length-prefixed
    bool is_json = (!is_length_prefixed && json_buffer[0] == '{');

    ESP_LOGI(TAG, "Content type: %s",
             is_zstd ? "zstd" :
             is_gzip ? "gzip" :
             is_length_prefixed ? "length-prefixed JSON" :
             is_json ? "JSON" : "unknown");

    char *json_str = NULL;
    size_t json_str_len = 0;

    if (is_zstd) {
        // Tailscale uses zstd compression for MapResponse
        // For now, we need to request uncompressed responses or add zstd decompression
        ESP_LOGW(TAG, "Response is zstd compressed - decompression not yet implemented");
        ESP_LOGW(TAG, "TODO: Add 'compress: false' to MapRequest or implement zstd");
        free(json_buffer);
        ml->coordination.last_map_poll_ms = microlink_get_time_ms();
        return ESP_OK;
    } else if (is_gzip) {
        ESP_LOGW(TAG, "Response is gzip compressed - not supported");
        free(json_buffer);
        ml->coordination.last_map_poll_ms = microlink_get_time_ms();
        return ESP_OK;
    } else if (is_length_prefixed) {
        // Tailscale binary framing: 4-byte length prefix followed by JSON
        // Skip the 4-byte header, JSON starts at offset 4
        json_str = (char *)json_buffer + 4;
        json_str_len = json_total_len - 4;
        ESP_LOGI(TAG, "Skipping 4-byte length prefix, JSON at offset 4");
    } else if (is_json) {
        json_str = (char *)json_buffer;
        json_str_len = json_total_len;
    } else {
        // Unknown format - try to parse anyway
        ESP_LOGW(TAG, "Unknown response format, attempting JSON parse");
        json_str = (char *)json_buffer;
        json_str_len = json_total_len;
    }

    // Null-terminate the JSON string (json_str may point to offset 4 for KV-prefixed)
    if (json_str && json_str_len > 0) {
        json_str[json_str_len] = '\0';
    }

    ESP_LOGI(TAG, "MapResponse JSON (%u bytes): %.200s%s", (unsigned int)json_str_len, json_str, json_str_len > 200 ? "..." : "");

    cJSON *root = cJSON_Parse(json_str);

    if (!root) {
        ESP_LOGE(TAG, "Failed to parse MapResponse JSON (len=%u)", (unsigned int)json_str_len);
        // Log the first 64 bytes to help debug the format
        if (json_str && json_str_len > 0) {
            ESP_LOGE(TAG, "JSON start: %.64s", json_str);
        }
        // Check cJSON error position
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            ESP_LOGE(TAG, "cJSON error near offset: %td", error_ptr - json_str);
        }
        free(json_buffer);  // Free after logging
        return ESP_FAIL;
    }

    free(json_buffer);  // json_str points to json_buffer, safe to free after cJSON_Parse copies it

    // Debug: List all top-level fields in the MapResponse
    ESP_LOGI(TAG, "MapResponse top-level fields:");
    cJSON *field = NULL;
    cJSON_ArrayForEach(field, root) {
        if (field->string) {
            if (cJSON_IsArray(field)) {
                ESP_LOGI(TAG, "  - %s (array, size=%d)", field->string, cJSON_GetArraySize(field));
            } else if (cJSON_IsObject(field)) {
                ESP_LOGI(TAG, "  - %s (object)", field->string);
            } else if (cJSON_IsString(field)) {
                ESP_LOGI(TAG, "  - %s (string): %.40s...", field->string, field->valuestring);
            } else if (cJSON_IsNumber(field)) {
                ESP_LOGI(TAG, "  - %s (number): %g", field->string, field->valuedouble);
            } else if (cJSON_IsBool(field)) {
                ESP_LOGI(TAG, "  - %s (bool): %s", field->string, cJSON_IsTrue(field) ? "true" : "false");
            } else {
                ESP_LOGI(TAG, "  - %s (other)", field->string);
            }
        }
    }

    // Extract Node.Addresses for VPN IP
    cJSON *node = cJSON_GetObjectItem(root, "Node");
    if (node) {
        cJSON *addresses = cJSON_GetObjectItem(node, "Addresses");
        if (addresses && cJSON_IsArray(addresses)) {
            cJSON *addr = cJSON_GetArrayItem(addresses, 0);
            if (addr && cJSON_IsString(addr)) {
                unsigned int a, b, c, d;
                if (sscanf(addr->valuestring, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    ml->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                    ESP_LOGI(TAG, "*** VPN IP assigned: %s ***", addr->valuestring);

                    // Update WireGuard interface
                    microlink_wireguard_set_vpn_ip(ml, ml->vpn_ip);
                }
            }
        }
    }

    // ========================================================================
    // Parse DERPMap for dynamic DERP region discovery (optional feature)
    // ========================================================================
    // When MICROLINK_DERP_DYNAMIC_DISCOVERY is enabled, parse available DERP
    // regions from the MapResponse. This handles cases where the tailnet has
    // custom derpMap configurations that disable certain regions.
    //
    // DERPMap structure (simplified):
    // {
    //   "Regions": {
    //     "1": { "RegionID": 1, "RegionCode": "nyc", "Nodes": [{"HostName": "derp1.tailscale.com", ...}] },
    //     "9": { "RegionID": 9, "RegionCode": "dfw", "Nodes": [{"HostName": "derp9d.tailscale.com", ...}] }
    //   }
    // }
    // Regions set to null in derpMap are omitted from this response.
#ifdef CONFIG_MICROLINK_DERP_DYNAMIC_DISCOVERY
    if (ml->derp.dynamic_discovery_enabled) {
        cJSON *derp_map = cJSON_GetObjectItem(root, "DERPMap");
        if (derp_map) {
            cJSON *regions = cJSON_GetObjectItem(derp_map, "Regions");
            if (regions && cJSON_IsObject(regions)) {
                ml->derp.region_count = 0;

                cJSON *region = NULL;
                cJSON_ArrayForEach(region, regions) {
                    if (ml->derp.region_count >= MICROLINK_MAX_DERP_REGIONS) {
                        ESP_LOGW(TAG, "DERPMap: Max regions (%d) reached, ignoring rest",
                                 MICROLINK_MAX_DERP_REGIONS);
                        break;
                    }

                    if (!cJSON_IsObject(region)) continue;

                    cJSON *region_id = cJSON_GetObjectItem(region, "RegionID");
                    cJSON *nodes = cJSON_GetObjectItem(region, "Nodes");

                    if (!region_id || !cJSON_IsNumber(region_id)) continue;
                    if (!nodes || !cJSON_IsArray(nodes) || cJSON_GetArraySize(nodes) == 0) continue;

                    // Get first node's hostname
                    cJSON *first_node = cJSON_GetArrayItem(nodes, 0);
                    if (!first_node) continue;

                    cJSON *hostname = cJSON_GetObjectItem(first_node, "HostName");
                    if (!hostname || !cJSON_IsString(hostname)) continue;

                    // Store this region
                    microlink_derp_region_t *r = &ml->derp.regions[ml->derp.region_count];
                    r->region_id = (uint16_t)region_id->valueint;
                    strncpy(r->hostname, hostname->valuestring, sizeof(r->hostname) - 1);
                    r->hostname[sizeof(r->hostname) - 1] = '\0';
                    r->port = 443;  // Default DERP port
                    r->available = true;

                    // Check for custom port in DERPPort field
                    cJSON *derp_port = cJSON_GetObjectItem(first_node, "DERPPort");
                    if (derp_port && cJSON_IsNumber(derp_port) && derp_port->valueint > 0) {
                        r->port = (uint16_t)derp_port->valueint;
                    }

                    ESP_LOGI(TAG, "DERPMap: Region %d -> %s:%d",
                             r->region_id, r->hostname, r->port);
                    ml->derp.region_count++;
                }

                if (ml->derp.region_count > 0) {
                    ESP_LOGI(TAG, "DERPMap: Discovered %d available DERP regions",
                             ml->derp.region_count);
                } else {
                    ESP_LOGW(TAG, "DERPMap: No valid regions found, falling back to hardcoded");
                }
            }
        } else {
            ESP_LOGD(TAG, "DERPMap: Not present in MapResponse (using hardcoded DERP)");
        }
    }
#endif  // CONFIG_MICROLINK_DERP_DYNAMIC_DISCOVERY

    // Extract peers from MapResponse
    // Tailscale uses different field names depending on the response type:
    // - "Peers": Full peer list (initial response with Stream=false)
    // - "PeersChanged": Incremental updates (Stream=true long-poll mode)
    // - "PeersChangedPatch": Partial updates to existing peers
    cJSON *peers_json = cJSON_GetObjectItem(root, "Peers");
    if (!peers_json) {
        peers_json = cJSON_GetObjectItem(root, "PeersChanged");  // Long-poll incremental updates
        if (peers_json) {
            ESP_LOGI(TAG, "Using 'PeersChanged' field for peer list");
        }
    }
    if (!peers_json) {
        peers_json = cJSON_GetObjectItem(root, "peers");  // Try lowercase
    }

    if (!peers_json) {
        ESP_LOGW(TAG, "No 'Peers' or 'PeersChanged' field found in MapResponse");
    } else if (!cJSON_IsArray(peers_json)) {
        ESP_LOGW(TAG, "Peers field is not an array (type=%d)", peers_json->type);
    }

    if (peers_json && cJSON_IsArray(peers_json)) {
        int json_peer_count = cJSON_GetArraySize(peers_json);
        ESP_LOGI(TAG, "Found %d peers in network map", json_peer_count);

        // Clear existing peers
        ml->peer_count = 0;
        memset(ml->peers, 0, sizeof(ml->peers));
        memset(ml->peer_map, 0xFF, sizeof(ml->peer_map));  // 0xFF = invalid index

        // Parse each peer (up to MICROLINK_MAX_PEERS)
        int added_peers = 0;
        cJSON *peer_json = NULL;
        cJSON_ArrayForEach(peer_json, peers_json) {
            if (added_peers >= MICROLINK_MAX_PEERS) {
                ESP_LOGW(TAG, "Max peers reached (%d), skipping remaining", MICROLINK_MAX_PEERS);
                break;
            }

            microlink_peer_t *peer = &ml->peers[added_peers];
            memset(peer, 0, sizeof(microlink_peer_t));

            // Extract Node ID
            cJSON *id = cJSON_GetObjectItem(peer_json, "ID");
            if (id && cJSON_IsNumber(id)) {
                peer->node_id = (uint32_t)id->valuedouble;
            }

            // Extract Name (hostname)
            cJSON *name = cJSON_GetObjectItem(peer_json, "Name");
            if (name && cJSON_IsString(name)) {
                strncpy(peer->hostname, name->valuestring, sizeof(peer->hostname) - 1);
                // Remove trailing dot if present
                size_t len = strlen(peer->hostname);
                if (len > 0 && peer->hostname[len - 1] == '.') {
                    peer->hostname[len - 1] = '\0';
                }
            }

            // Extract Key (WireGuard public key in "nodekey:hex" format)
            cJSON *key = cJSON_GetObjectItem(peer_json, "Key");
            if (key && cJSON_IsString(key)) {
                const char *key_str = key->valuestring;
                // Skip "nodekey:" prefix if present
                if (strncmp(key_str, "nodekey:", 8) == 0) {
                    key_str += 8;
                }
                // Parse 64 hex characters into 32 bytes
                for (int i = 0; i < 32 && key_str[i * 2] && key_str[i * 2 + 1]; i++) {
                    char hex[3] = {key_str[i * 2], key_str[i * 2 + 1], '\0'};
                    peer->public_key[i] = (uint8_t)strtoul(hex, NULL, 16);
                }
            }

            // Extract DiscoKey (DISCO public key in "discokey:hex" format)
            cJSON *disco_key_json = cJSON_GetObjectItem(peer_json, "DiscoKey");
            if (disco_key_json && cJSON_IsString(disco_key_json)) {
                const char *disco_str = disco_key_json->valuestring;
                // Skip "discokey:" prefix if present
                if (strncmp(disco_str, "discokey:", 9) == 0) {
                    disco_str += 9;
                }
                // Parse 64 hex characters into 32 bytes
                for (int i = 0; i < 32 && disco_str[i * 2] && disco_str[i * 2 + 1]; i++) {
                    char hex[3] = {disco_str[i * 2], disco_str[i * 2 + 1], '\0'};
                    peer->disco_key[i] = (uint8_t)strtoul(hex, NULL, 16);
                }
                ESP_LOGD(TAG, "Peer %d DiscoKey: %02x%02x%02x%02x...",
                         ml->peer_count, peer->disco_key[0], peer->disco_key[1],
                         peer->disco_key[2], peer->disco_key[3]);
            } else {
                // If no DiscoKey, use WireGuard key as fallback (old behavior)
                memcpy(peer->disco_key, peer->public_key, 32);
                ESP_LOGD(TAG, "Peer %d has no DiscoKey, using WireGuard key", ml->peer_count);
            }

            // Extract Addresses (VPN IP)
            cJSON *addresses = cJSON_GetObjectItem(peer_json, "Addresses");
            if (addresses && cJSON_IsArray(addresses)) {
                cJSON *addr = cJSON_GetArrayItem(addresses, 0);
                if (addr && cJSON_IsString(addr)) {
                    unsigned int a, b, c, d;
                    if (sscanf(addr->valuestring, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                        peer->vpn_ip = (a << 24) | (b << 16) | (c << 8) | d;
                    }
                }
            }

            // Extract Endpoints (direct UDP addresses in "ip:port" format)
            cJSON *endpoints = cJSON_GetObjectItem(peer_json, "Endpoints");
            if (endpoints && cJSON_IsArray(endpoints)) {
                cJSON *ep = NULL;
                int ep_idx = 0;
                cJSON_ArrayForEach(ep, endpoints) {
                    if (ep_idx >= MICROLINK_MAX_ENDPOINTS) break;
                    if (cJSON_IsString(ep)) {
                        unsigned int ea, eb, ec, ed, eport;
                        if (sscanf(ep->valuestring, "%u.%u.%u.%u:%u", &ea, &eb, &ec, &ed, &eport) == 5) {
                            peer->endpoints[ep_idx].addr.ip4 = htonl((ea << 24) | (eb << 16) | (ec << 8) | ed);
                            peer->endpoints[ep_idx].port = (uint16_t)eport;
                            peer->endpoints[ep_idx].is_ipv6 = 0;
                            peer->endpoints[ep_idx].is_derp = 0;
                            ep_idx++;
                        }
                    }
                }
                peer->endpoint_count = ep_idx;
            }

            // Check for DERP region (indicates peer prefers DERP relay)
            cJSON *derp = cJSON_GetObjectItem(peer_json, "DERP");
            if (!derp) {
                derp = cJSON_GetObjectItem(peer_json, "HomeDERP");
            }
            if (derp && cJSON_IsString(derp) && strlen(derp->valuestring) > 0) {
                // Peer has a DERP home region - add as fallback endpoint
                // Format is typically "127.3.3.40:N" where N is region ID
                // For now, just note it exists - DERP connection handled separately
                ESP_LOGD(TAG, "Peer %s has DERP: %s", peer->hostname, derp->valuestring);
            }

            // Only add peer if we got essential fields
            if (peer->vpn_ip != 0 && peer->hostname[0] != '\0') {
                // Add to peer map for quick lookup by VPN IP last byte
                uint8_t last_byte = peer->vpn_ip & 0xFF;
                ml->peer_map[last_byte] = added_peers;

                ESP_LOGI(TAG, "Peer %d: %s (VPN: %d.%d.%d.%d, endpoints: %d)",
                         added_peers, peer->hostname,
                         (peer->vpn_ip >> 24) & 0xFF,
                         (peer->vpn_ip >> 16) & 0xFF,
                         (peer->vpn_ip >> 8) & 0xFF,
                         peer->vpn_ip & 0xFF,
                         peer->endpoint_count);

                added_peers++;
            }
        }

        ml->peer_count = added_peers;
        ESP_LOGI(TAG, "Parsed %d peers into peer table", added_peers);
    }

    cJSON_Delete(root);
    ml->coordination.last_map_poll_ms = microlink_get_time_ms();

    // ========================================================================
    // STEP 2: Send Stream=true MapRequest to start long-poll mode
    // ========================================================================
    // Now that DERPRegion is set via the Stream=false request above,
    // we need to start a long-poll to maintain "online" status.
    ESP_LOGI(TAG, "Starting long-poll with Stream=true...");

    // Build minimal MapRequest for long-poll
    cJSON *longpoll_req = cJSON_CreateObject();
    cJSON_AddNumberToObject(longpoll_req, "Version", TAILSCALE_PROTOCOL_VERSION);

    // NodeKey
    char nodekey_str2[80];
    uint8_t *wg_pubkey2 = ml->wireguard.public_key;
    char nodekey_hex2[65];
    for (int k = 0; k < 32; k++) {
        sprintf(&nodekey_hex2[k * 2], "%02x", wg_pubkey2[k]);
    }
    snprintf(nodekey_str2, sizeof(nodekey_str2), "nodekey:%s", nodekey_hex2);
    cJSON_AddStringToObject(longpoll_req, "NodeKey", nodekey_str2);

    // DiscoKey - required for long-poll
    uint8_t *disco_pubkey2 = ml->wireguard.disco_public_key;
    char discokey_hex2[65];
    for (int k = 0; k < 32; k++) {
        sprintf(&discokey_hex2[k * 2], "%02x", disco_pubkey2[k]);
    }
    char discokey_str2[80];
    snprintf(discokey_str2, sizeof(discokey_str2), "discokey:%s", discokey_hex2);
    cJSON_AddStringToObject(longpoll_req, "DiscoKey", discokey_str2);

    // Hostinfo - REQUIRED even for Stream=true (server may ignore but validates presence)
    cJSON *hostinfo2 = cJSON_CreateObject();
    cJSON_AddStringToObject(hostinfo2, "Hostname", ml->config.device_name);
    cJSON_AddStringToObject(hostinfo2, "OS", "linux");
    cJSON_AddStringToObject(hostinfo2, "OSVersion", "ESP-IDF");
    cJSON_AddStringToObject(hostinfo2, "GoArch", "arm");
    cJSON_AddItemToObject(longpoll_req, "Hostinfo", hostinfo2);

    // Endpoints - included like official client does (server ignores for Stream=true but may validate)
    if (ml->stun.public_ip != 0 && ml->stun.public_port != 0) {
        cJSON *endpoints2 = cJSON_CreateArray();
        char ep_str2[64];
        snprintf(ep_str2, sizeof(ep_str2), "%d.%d.%d.%d:%u",
                 (ml->stun.public_ip >> 24) & 0xFF,
                 (ml->stun.public_ip >> 16) & 0xFF,
                 (ml->stun.public_ip >> 8) & 0xFF,
                 ml->stun.public_ip & 0xFF,
                 ml->stun.public_port);
        cJSON_AddItemToArray(endpoints2, cJSON_CreateString(ep_str2));
        cJSON_AddItemToObject(longpoll_req, "Endpoints", endpoints2);
    }

    // Stream=true for long-poll
    cJSON_AddBoolToObject(longpoll_req, "Stream", true);
    cJSON_AddBoolToObject(longpoll_req, "KeepAlive", true);  // CRITICAL: Required for Stream=true!
    cJSON_AddStringToObject(longpoll_req, "Compress", "");   // Disable compression - empty string means no compression
    cJSON_AddBoolToObject(longpoll_req, "OmitPeers", true);  // We already have peers

    char *longpoll_str = cJSON_PrintUnformatted(longpoll_req);
    cJSON_Delete(longpoll_req);

    if (longpoll_str) {
        size_t longpoll_json_len = strlen(longpoll_str);
        ESP_LOGI(TAG, "Long-poll MapRequest (%u bytes): %s", (unsigned int)longpoll_json_len, longpoll_str);

        // Build HTTP/2 frame for long-poll request
        uint8_t longpoll_hpack[128];
        size_t longpoll_hpack_len = 0;
        longpoll_hpack[longpoll_hpack_len++] = 0x83;  // :method = POST
        longpoll_hpack[longpoll_hpack_len++] = 0x86;  // :scheme = https
        longpoll_hpack[longpoll_hpack_len++] = 0x44;  // :path (literal)
        longpoll_hpack[longpoll_hpack_len++] = 0x0c;  // path length
        memcpy(longpoll_hpack + longpoll_hpack_len, "/machine/map", 12);
        longpoll_hpack_len += 12;
        longpoll_hpack[longpoll_hpack_len++] = 0x41;  // :authority (literal indexed name)
        longpoll_hpack[longpoll_hpack_len++] = 0x1a;  // length 26
        memcpy(longpoll_hpack + longpoll_hpack_len, "controlplane.tailscale.com", 26);
        longpoll_hpack_len += 26;
        // content-type: application/json (literal without indexing, full name/value)
        longpoll_hpack[longpoll_hpack_len++] = 0x00;  // Literal header without indexing
        longpoll_hpack[longpoll_hpack_len++] = 0x0c;  // Name length = 12
        memcpy(longpoll_hpack + longpoll_hpack_len, "content-type", 12);
        longpoll_hpack_len += 12;
        longpoll_hpack[longpoll_hpack_len++] = 0x10;  // Value length = 16
        memcpy(longpoll_hpack + longpoll_hpack_len, "application/json", 16);
        longpoll_hpack_len += 16;

        // Use next odd stream ID for HTTP/2
        uint32_t longpoll_stream_id = ml->coordination.next_stream_id;
        ml->coordination.next_stream_id += 2;

        // HEADERS frame
        size_t longpoll_h2_len = 9 + longpoll_hpack_len + 9 + longpoll_json_len;
        uint8_t *longpoll_h2 = malloc(longpoll_h2_len);
        if (longpoll_h2) {
            size_t off = 0;
            // HEADERS frame
            longpoll_h2[off++] = (longpoll_hpack_len >> 16) & 0xFF;
            longpoll_h2[off++] = (longpoll_hpack_len >> 8) & 0xFF;
            longpoll_h2[off++] = longpoll_hpack_len & 0xFF;
            longpoll_h2[off++] = 0x01;  // HEADERS
            longpoll_h2[off++] = 0x04;  // END_HEADERS
            longpoll_h2[off++] = (longpoll_stream_id >> 24) & 0xFF;
            longpoll_h2[off++] = (longpoll_stream_id >> 16) & 0xFF;
            longpoll_h2[off++] = (longpoll_stream_id >> 8) & 0xFF;
            longpoll_h2[off++] = longpoll_stream_id & 0xFF;
            memcpy(longpoll_h2 + off, longpoll_hpack, longpoll_hpack_len);
            off += longpoll_hpack_len;

            // DATA frame with END_STREAM
            longpoll_h2[off++] = (longpoll_json_len >> 16) & 0xFF;
            longpoll_h2[off++] = (longpoll_json_len >> 8) & 0xFF;
            longpoll_h2[off++] = longpoll_json_len & 0xFF;
            longpoll_h2[off++] = 0x00;  // DATA
            longpoll_h2[off++] = 0x01;  // END_STREAM
            longpoll_h2[off++] = (longpoll_stream_id >> 24) & 0xFF;
            longpoll_h2[off++] = (longpoll_stream_id >> 16) & 0xFF;
            longpoll_h2[off++] = (longpoll_stream_id >> 8) & 0xFF;
            longpoll_h2[off++] = longpoll_stream_id & 0xFF;
            memcpy(longpoll_h2 + off, longpoll_str, longpoll_json_len);
            off += longpoll_json_len;

            // Encrypt and send
            size_t enc_size = off + 16;
            uint8_t *enc_buf = malloc(3 + enc_size);
            if (enc_buf) {
                enc_buf[0] = 0x04;
                enc_buf[1] = (enc_size >> 8) & 0xFF;
                enc_buf[2] = enc_size & 0xFF;

                ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                    NULL, 0, longpoll_h2, off, enc_buf + 3);
                if (ret == ESP_OK) {
                    int sent = send(ml->coordination.socket, enc_buf, 3 + enc_size, 0);
                    if (sent == 3 + enc_size) {
                        ESP_LOGI(TAG, "Long-poll MapRequest sent on stream %lu", (unsigned long)longpoll_stream_id);

                        // Send an initial HTTP/2 PING immediately to keep the connection active
                        // The server has a ~20 second idle timeout, so we need to send something
                        // before the first heartbeat poll (which might be 10+ seconds away)
                        uint8_t ping_frame[17];
                        ping_frame[0] = 0x00;
                        ping_frame[1] = 0x00;
                        ping_frame[2] = 0x08;
                        ping_frame[3] = 0x06;  // PING
                        ping_frame[4] = 0x00;
                        ping_frame[5] = 0x00;
                        ping_frame[6] = 0x00;
                        ping_frame[7] = 0x00;
                        ping_frame[8] = 0x00;
                        // Use a simple payload
                        memset(ping_frame + 9, 0x42, 8);

                        size_t ping_enc_len = sizeof(ping_frame) + 16;
                        uint8_t *ping_buf = malloc(3 + ping_enc_len);
                        if (ping_buf) {
                            ping_buf[0] = 0x04;
                            ping_buf[1] = (ping_enc_len >> 8) & 0xFF;
                            ping_buf[2] = ping_enc_len & 0xFF;
                            if (noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                              NULL, 0, ping_frame, sizeof(ping_frame), ping_buf + 3) == ESP_OK) {
                                int ping_sent = send(ml->coordination.socket, ping_buf, 3 + ping_enc_len, 0);
                                ESP_LOGI(TAG, "Sent initial HTTP/2 PING after long-poll (sent=%d)", ping_sent);
                                ml->coordination.last_ping_ms = microlink_get_time_ms();  // Sync with poll_updates
                                // NOTE: Don't try to read PONG here - let poll_updates handle it
                                // Reading here would desync rx_nonce and cause frame misalignment
                            }
                            free(ping_buf);
                        }

                        // === Start the poll task NOW, immediately after long-poll is established ===
                        // This is critical: we must start polling BEFORE any server responses arrive
                        // to avoid nonce desync. The poll task will handle all incoming data from here.
                        esp_err_t poll_ret = microlink_coordination_start_poll_task(ml);
                        if (poll_ret != ESP_OK) {
                            ESP_LOGW(TAG, "Failed to start coordination poll task: %d", poll_ret);
                            // Continue anyway - we'll fall back to single-core mode
                        }
                    } else {
                        ESP_LOGW(TAG, "Failed to send long-poll: sent=%d", sent);
                    }
                }
                free(enc_buf);
            }
            free(longpoll_h2);
        }
        free(longpoll_str);
    }

    return ESP_OK;
}

esp_err_t microlink_coordination_heartbeat(microlink_t *ml) {
    // Check if we have an active Noise session
    if (!ml->coordination.handshake_complete || ml->coordination.socket < 0) {
        ESP_LOGW(TAG, "No active session for heartbeat, need re-registration");
        ml->coordination.registered = false;
        return ESP_ERR_INVALID_STATE;
    }

    int sock = ml->coordination.socket;

    // Verify socket is still connected
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
        ESP_LOGE(TAG, "Socket %d is dead: getsockopt error=%d", sock, error);
        // CRITICAL: Close the dead socket to avoid file descriptor leak
        close(sock);
        ml->coordination.socket = -1;
        ml->coordination.handshake_complete = false;
        ml->coordination.registered = false;
        ml->coordination.last_ping_ms = 0;  // Reset so next connection sends PING immediately
        return ESP_ERR_INVALID_STATE;
    }

    // IMPORTANT: In Stream=true (long-poll) mode, the connection already maintains
    // "online" status. Sending Stream=false requests on the same HTTP/2 connection
    // breaks the protocol and causes the server to close the connection.
    //
    // We only need to send endpoint updates when we have NEW STUN-discovered endpoints.
    // Since STUN discovery isn't working yet, skip the heartbeat to keep the connection alive.
    if (1) {
        ESP_LOGI(TAG, "Heartbeat skipped: no STUN endpoints to advertise (long-poll maintains online status)");
        ml->coordination.last_heartbeat_ms = microlink_get_time_ms();
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Sending endpoint update (Stream=false, OmitPeers=true)");
    ESP_LOGI(TAG, "Socket %d appears valid, sending heartbeat...", sock);

    // Build MapRequest to advertise our endpoints
    // CRITICAL: Per Tailscale protocol (capver >= 68), Stream=true means server
    // IGNORES Hostinfo and Endpoints! We must use Stream=false with OmitPeers=true
    // to update our endpoint information. The server returns just HTTP 200 OK.
    cJSON *map_req = cJSON_CreateObject();
    cJSON_AddNumberToObject(map_req, "Version", TAILSCALE_PROTOCOL_VERSION);
    cJSON_AddBoolToObject(map_req, "Stream", false);    // Non-streaming for endpoint updates
    cJSON_AddBoolToObject(map_req, "OmitPeers", true);  // Server returns minimal response
    cJSON_AddStringToObject(map_req, "Compress", "");   // Disable compression - empty string means no compression

    // Include NodeKey so server knows who we are
    uint8_t *wg_pubkey = ml->wireguard.public_key;
    char nodekey_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(nodekey_hex + i * 2, 3, "%02x", wg_pubkey[i]);
    }
    char nodekey_str[80];
    snprintf(nodekey_str, sizeof(nodekey_str), "nodekey:%s", nodekey_hex);
    cJSON_AddStringToObject(map_req, "NodeKey", nodekey_str);

    // Include DiscoKey
    char discokey_hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(discokey_hex + i * 2, 3, "%02x", ml->wireguard.disco_public_key[i]);
    }
    char discokey_str[80];
    snprintf(discokey_str, sizeof(discokey_str), "discokey:%s", discokey_hex);
    cJSON_AddStringToObject(map_req, "DiscoKey", discokey_str);

    // Hostinfo - include device info with endpoint updates
    cJSON *hostinfo = cJSON_CreateObject();
    cJSON_AddStringToObject(hostinfo, "Hostname", ml->config.device_name);
    cJSON_AddStringToObject(hostinfo, "OS", "linux");
    cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
    cJSON_AddStringToObject(hostinfo, "GoArch", "arm");

    // NetInfo with PreferredDERP - CRITICAL for DERP routing!
    cJSON *netinfo = cJSON_CreateObject();
    cJSON_AddNumberToObject(netinfo, "PreferredDERP", MICROLINK_DERP_REGION);  // Must match DERP server!
    cJSON_AddBoolToObject(netinfo, "WorkingUDP", true);
    cJSON_AddBoolToObject(netinfo, "WorkingIPv6", false);
    cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);

    cJSON_AddItemToObject(map_req, "Hostinfo", hostinfo);

    // Include Endpoints - both local and STUN (CRITICAL for peers to reach us!)
    {
        cJSON *endpoints = cJSON_CreateArray();
        cJSON *endpoint_types = cJSON_CreateArray();
        int endpoint_count = 0;

        // Add local WiFi endpoint (EndpointLocal = 1)
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        esp_netif_ip_info_t ip_info;
        if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            char local_ep[32];
            snprintf(local_ep, sizeof(local_ep), "%d.%d.%d.%d:%u",
                     (ip_info.ip.addr) & 0xFF,
                     (ip_info.ip.addr >> 8) & 0xFF,
                     (ip_info.ip.addr >> 16) & 0xFF,
                     (ip_info.ip.addr >> 24) & 0xFF,
                     ml->wireguard.listen_port);
            cJSON_AddItemToArray(endpoints, cJSON_CreateString(local_ep));
            cJSON_AddItemToArray(endpoint_types, cJSON_CreateNumber(1));  // EndpointLocal
            endpoint_count++;
        }

        // Add STUN endpoint (EndpointSTUN = 2) if available
        if (ml->stun.public_ip != 0 && ml->stun.public_port != 0) {
            char stun_ep[32];
            snprintf(stun_ep, sizeof(stun_ep), "%lu.%lu.%lu.%lu:%u",
                     (unsigned long)((ml->stun.public_ip >> 24) & 0xFF),
                     (unsigned long)((ml->stun.public_ip >> 16) & 0xFF),
                     (unsigned long)((ml->stun.public_ip >> 8) & 0xFF),
                     (unsigned long)(ml->stun.public_ip & 0xFF),
                     ml->stun.public_port);
            cJSON_AddItemToArray(endpoints, cJSON_CreateString(stun_ep));
            cJSON_AddItemToArray(endpoint_types, cJSON_CreateNumber(2));  // EndpointSTUN
            endpoint_count++;
        }

        if (endpoint_count > 0) {
            cJSON_AddItemToObject(map_req, "Endpoints", endpoints);
            cJSON_AddItemToObject(map_req, "EndpointTypes", endpoint_types);
            ESP_LOGI(TAG, "Heartbeat advertising %d endpoints", endpoint_count);
        } else {
            cJSON_Delete(endpoints);
            cJSON_Delete(endpoint_types);
        }
    }

    char *map_req_str = cJSON_PrintUnformatted(map_req);
    cJSON_Delete(map_req);

    if (!map_req_str) {
        ESP_LOGE(TAG, "Failed to serialize heartbeat MapRequest");
        return ESP_ERR_NO_MEM;
    }

    size_t json_len = strlen(map_req_str);
    ESP_LOGI(TAG, "Heartbeat MapRequest: %s", map_req_str);

    // Build HPACK headers for /machine/map
    uint8_t hpack_headers[256];
    int hpack_len = 0;
    hpack_headers[hpack_len++] = 0x82;  // :method = POST
    hpack_headers[hpack_len++] = 0x84;  // :path = /machine/map (indexed)
    static const char *path_value = "/machine/map";
    hpack_headers[hpack_len++] = 0x04;
    hpack_headers[hpack_len++] = strlen(path_value);
    memcpy(hpack_headers + hpack_len, path_value, strlen(path_value));
    hpack_len += strlen(path_value);
    hpack_headers[hpack_len++] = 0x86;  // :scheme = https
    static const char *ct_value = "application/json";
    hpack_headers[hpack_len++] = 0x1f;
    hpack_headers[hpack_len++] = 0x10;
    hpack_headers[hpack_len++] = strlen(ct_value);
    memcpy(hpack_headers + hpack_len, ct_value, strlen(ct_value));
    hpack_len += strlen(ct_value);

    // Get next stream ID
    uint32_t stream_id = ml->coordination.next_stream_id;
    ml->coordination.next_stream_id += 2;

    // Build HTTP/2 HEADERS frame
    uint8_t h2_headers_frame[9 + 256];
    h2_headers_frame[0] = (hpack_len >> 16) & 0xFF;
    h2_headers_frame[1] = (hpack_len >> 8) & 0xFF;
    h2_headers_frame[2] = hpack_len & 0xFF;
    h2_headers_frame[3] = 0x01;  // HEADERS
    h2_headers_frame[4] = 0x04;  // END_HEADERS
    h2_headers_frame[5] = (stream_id >> 24) & 0x7F;
    h2_headers_frame[6] = (stream_id >> 16) & 0xFF;
    h2_headers_frame[7] = (stream_id >> 8) & 0xFF;
    h2_headers_frame[8] = stream_id & 0xFF;
    memcpy(h2_headers_frame + 9, hpack_headers, hpack_len);
    int headers_frame_len = 9 + hpack_len;

    // Build HTTP/2 DATA frame
    uint8_t *h2_data_frame = malloc(9 + json_len);
    if (!h2_data_frame) {
        free(map_req_str);
        return ESP_ERR_NO_MEM;
    }
    h2_data_frame[0] = (json_len >> 16) & 0xFF;
    h2_data_frame[1] = (json_len >> 8) & 0xFF;
    h2_data_frame[2] = json_len & 0xFF;
    h2_data_frame[3] = 0x00;  // DATA
    h2_data_frame[4] = 0x01;  // END_STREAM
    h2_data_frame[5] = (stream_id >> 24) & 0x7F;
    h2_data_frame[6] = (stream_id >> 16) & 0xFF;
    h2_data_frame[7] = (stream_id >> 8) & 0xFF;
    h2_data_frame[8] = stream_id & 0xFF;
    memcpy(h2_data_frame + 9, map_req_str, json_len);
    int data_frame_len = 9 + json_len;
    free(map_req_str);

    // Combine frames
    int total_h2_len = headers_frame_len + data_frame_len;
    uint8_t *enc_buf = malloc(3 + total_h2_len + NOISE_MAC_LEN);
    if (!enc_buf) {
        free(h2_data_frame);
        return ESP_ERR_NO_MEM;
    }

    memcpy(enc_buf + 3, h2_headers_frame, headers_frame_len);
    memcpy(enc_buf + 3 + headers_frame_len, h2_data_frame, data_frame_len);
    free(h2_data_frame);

    // Encrypt with Noise
    // noise_encrypt signature: (key, nonce, ad, ad_len, plaintext, plaintext_len, ciphertext)
    // For transport messages, no associated data (ad=NULL, ad_len=0)
    // Output ciphertext = plaintext + 16-byte MAC tag
    int enc_len = total_h2_len + NOISE_MAC_LEN;
    enc_buf[0] = 0x04;  // Noise transport message type
    enc_buf[1] = (enc_len >> 8) & 0xFF;
    enc_buf[2] = enc_len & 0xFF;

    // Copy plaintext to temp buffer since we can't encrypt in place
    uint8_t *plaintext = malloc(total_h2_len);
    if (!plaintext) {
        free(enc_buf);
        return ESP_ERR_NO_MEM;
    }
    memcpy(plaintext, enc_buf + 3, total_h2_len);

    esp_err_t ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                  NULL, 0,  // No associated data for transport messages
                                  plaintext, total_h2_len,
                                  enc_buf + 3);  // Ciphertext goes after 3-byte header
    free(plaintext);
    if (ret != ESP_OK) {
        free(enc_buf);
        ESP_LOGE(TAG, "Failed to encrypt heartbeat");
        return ret;
    }

    // Send: 3-byte header + encrypted payload (plaintext + MAC)
    int send_len = 3 + enc_len;
    int sent = send(sock, enc_buf, send_len, 0);
    free(enc_buf);

    if (sent != send_len) {
        ESP_LOGE(TAG, "Heartbeat send failed: sent=%d, expected=%d, errno=%d (%s)",
                 sent, send_len, errno, strerror(errno));
        // Socket is dead, close it and mark for reconnection
        close(sock);
        ml->coordination.socket = -1;
        ml->coordination.handshake_complete = false;
        ml->coordination.registered = false;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Heartbeat sent successfully on stream %lu", (unsigned long)stream_id);
    ml->coordination.last_heartbeat_ms = microlink_get_time_ms();
    return ESP_OK;
}

/**
 * @brief Handle key rotation and re-registration
 *
 * This should be called when:
 * - MapResponse indicates KeyExpiry
 * - Server returns NeedMachineAuth
 * - Connection is lost and needs re-establishment
 */
esp_err_t microlink_coordination_handle_key_rotation(microlink_t *ml) {
    ESP_LOGI(TAG, "Handling key rotation / re-registration");

    // Step 1: Close existing connections
    if (ml->coordination.socket >= 0) {
        close(ml->coordination.socket);
        ml->coordination.socket = -1;
    }

    // Step 2: Reset Noise session state
    ml->coordination.handshake_complete = false;
    ml->coordination.tx_nonce = 0;
    ml->coordination.rx_nonce = 0;
    memset(ml->coordination.tx_key, 0, sizeof(ml->coordination.tx_key));
    memset(ml->coordination.rx_key, 0, sizeof(ml->coordination.rx_key));

    // Step 3: Generate new ephemeral key (machine key stays the same)
    // The machine key is our long-term identity, only regenerate if explicitly requested

    // Step 4: Mark as needing registration
    ml->coordination.registered = false;

    ESP_LOGI(TAG, "Session reset complete, ready for re-registration");
    return ESP_OK;
}

/**
 * @brief Check if session is still valid and reconnect if needed
 *
 * Call this periodically to maintain connection health
 */
esp_err_t microlink_coordination_check_session(microlink_t *ml) {
    // Check socket validity
    if (ml->coordination.socket < 0) {
        ESP_LOGW(TAG, "Socket invalid, need reconnection");
        return ESP_ERR_INVALID_STATE;
    }

    // Check if handshake is complete
    if (!ml->coordination.handshake_complete) {
        ESP_LOGW(TAG, "Handshake not complete");
        return ESP_ERR_INVALID_STATE;
    }

    // Optionally: send a probe to check connection liveness
    // For now, we trust the TCP connection

    return ESP_OK;
}

/**
 * @brief Poll for long-poll updates from the coordination server
 *
 * In Stream=true mode, the server keeps the connection open and sends
 * updates when the network map changes. This function checks for and
 * processes any pending updates.
 *
 * This is critical for maintaining "online" status in Tailscale.
 */
esp_err_t microlink_coordination_poll_updates(microlink_t *ml) {
    if (!ml->coordination.handshake_complete || ml->coordination.socket < 0) {
        return ESP_ERR_INVALID_STATE;
    }

    int sock = ml->coordination.socket;
    esp_err_t ret = ESP_OK;

    // Send HTTP/2 PING every 5 seconds to keep the connection alive
    // The Tailscale server appears to have a ~20 second idle timeout, but
    // we need frequent pings to ensure bidirectional activity
    uint64_t now = microlink_get_time_ms();
    if (ml->coordination.last_ping_ms == 0 || (now - ml->coordination.last_ping_ms) >= 5000) {
        // Build HTTP/2 PING frame (opaque 8-byte payload)
        uint8_t ping_frame[17];
        ping_frame[0] = 0x00;  // Length high
        ping_frame[1] = 0x00;  // Length mid
        ping_frame[2] = 0x08;  // Length low (8 bytes)
        ping_frame[3] = 0x06;  // Type: PING
        ping_frame[4] = 0x00;  // Flags: none (not ACK)
        ping_frame[5] = 0x00;  // Stream ID (always 0 for PING)
        ping_frame[6] = 0x00;
        ping_frame[7] = 0x00;
        ping_frame[8] = 0x00;
        // Opaque payload - use timestamp as unique identifier
        uint64_t ping_id = now;
        ping_frame[9] = (ping_id >> 56) & 0xFF;
        ping_frame[10] = (ping_id >> 48) & 0xFF;
        ping_frame[11] = (ping_id >> 40) & 0xFF;
        ping_frame[12] = (ping_id >> 32) & 0xFF;
        ping_frame[13] = (ping_id >> 24) & 0xFF;
        ping_frame[14] = (ping_id >> 16) & 0xFF;
        ping_frame[15] = (ping_id >> 8) & 0xFF;
        ping_frame[16] = ping_id & 0xFF;

        // Encrypt and send PING
        size_t enc_len = sizeof(ping_frame) + 16;
        uint8_t *enc_buf = malloc(3 + enc_len);
        if (enc_buf) {
            enc_buf[0] = 0x04;
            enc_buf[1] = (enc_len >> 8) & 0xFF;
            enc_buf[2] = enc_len & 0xFF;

            esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                              NULL, 0, ping_frame, sizeof(ping_frame), enc_buf + 3);
            if (enc_ret == ESP_OK) {
                int sent = send(sock, enc_buf, 3 + enc_len, 0);
                if (sent == 3 + (int)enc_len) {
                    ESP_LOGI(TAG, "Sent HTTP/2 PING to keep connection alive");
                    ml->coordination.last_ping_ms = now;
                } else {
                    ESP_LOGW(TAG, "Failed to send PING: sent=%d errno=%d", sent, errno);
                }
            }
            free(enc_buf);
        }
    }

    // Set socket to non-blocking for polling
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Buffer to accumulate TCP data (Noise frames can span multiple recv calls)
    uint8_t *tcp_buffer = malloc(8192);
    if (!tcp_buffer) {
        fcntl(sock, F_SETFL, flags);  // Restore blocking mode
        return ESP_ERR_NO_MEM;
    }
    size_t tcp_buffer_len = 0;
    int frames_processed = 0;
    int total_frames_processed = 0;
    int drain_iterations = 0;
    const int max_drain_iterations = 10;  // Safety limit to prevent infinite loop

    // Track stream ID from partial DATA frames for continuation handling
    static int last_partial_stream_id = 0;

    // CRITICAL: Loop to fully drain the socket
    // The server may send 22KB+ of data, but we only have 8KB buffer
    // Without this loop, we'd read 8KB, return, do DISCO, and the server times out
    // waiting for us to acknowledge the remaining data
    while (drain_iterations < max_drain_iterations) {
        drain_iterations++;
        tcp_buffer_len = 0;  // Reset buffer for this iteration
        frames_processed = 0;
        bool got_data = false;

        // Read all available data from socket into our buffer
        while (tcp_buffer_len < 8192) {
            int recv_len = recv(sock, tcp_buffer + tcp_buffer_len, 8192 - tcp_buffer_len, 0);

            if (recv_len <= 0) {
                if (recv_len == 0) {
                    // Connection closed by server
                    ESP_LOGW(TAG, "Long-poll connection closed by server");
                    ml->coordination.handshake_complete = false;
                    ml->coordination.last_ping_ms = 0;  // Reset for next connection
                    ret = ESP_ERR_INVALID_STATE;
                    goto cleanup;
                }
                // No more data available (EAGAIN/EWOULDBLOCK) or error
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Normal - no more data available right now
                    break;
                }
                // Real error
                ESP_LOGW(TAG, "Long-poll recv error: %d (errno=%d)", recv_len, errno);
                ml->coordination.handshake_complete = false;
                ml->coordination.last_ping_ms = 0;  // Reset for next connection
                ret = ESP_ERR_INVALID_STATE;
                goto cleanup;
            }

            tcp_buffer_len += recv_len;
            got_data = true;
            ESP_LOGD(TAG, "Poll recv: +%d bytes (total=%u)", recv_len, (unsigned int)tcp_buffer_len);
        }

        // If no data was read in this iteration, check if we should wait for more
        // The server sends complete messages (length-prefixed JSON), so if we've
        // started receiving data, we should try to read the complete message
        if (!got_data || tcp_buffer_len == 0) {
            // If we processed data in a previous iteration, give server time to send more
            // This handles the case where we've partially read a large response
            if (total_frames_processed > 0 && drain_iterations <= 5) {
                vTaskDelay(pdMS_TO_TICKS(20));  // Wait 20ms for more data
                continue;  // Try reading again
            }
            break;
        }

        // Process complete Noise frames from tcp_buffer
        size_t consumed = 0;
        int unexpected_count = 0;  // Limit logging per call

        // Debug: Log buffer info if we got data and first byte isn't 0x04
        if (tcp_buffer_len > 0 && tcp_buffer[0] != 0x04) {
            ESP_LOGW(TAG, "poll_updates: buffer not aligned! len=%u, rx_nonce=%lu, first 16 bytes:",
                     (unsigned int)tcp_buffer_len, (unsigned long)ml->coordination.rx_nonce);
            for (size_t i = 0; i < 16 && i < tcp_buffer_len; i++) {
                ESP_LOGW(TAG, "  [%u] = 0x%02x", (unsigned int)i, tcp_buffer[i]);
            }
        }

        while (consumed + 3 <= tcp_buffer_len && ret == ESP_OK) {
            // Check frame type (0x04 = Noise transport message)
            if (tcp_buffer[consumed] != 0x04) {
                // Only log first few unexpected bytes to avoid spam
                if (unexpected_count < 3) {
                    ESP_LOGW(TAG, "Unexpected frame type at offset %u: 0x%02x (total_len=%u, rx_nonce=%lu)",
                             (unsigned int)consumed, tcp_buffer[consumed], (unsigned int)tcp_buffer_len,
                             (unsigned long)ml->coordination.rx_nonce);
                    unexpected_count++;
                }
                consumed++;  // Skip unknown byte and try to resync
            continue;
        }

        // Get frame length (big-endian 16-bit)
        int payload_len = (tcp_buffer[consumed + 1] << 8) | tcp_buffer[consumed + 2];
        size_t frame_total = 3 + payload_len;

        // Check if we have the complete frame
        if (consumed + frame_total > tcp_buffer_len) {
            // Incomplete frame - this shouldn't happen in non-blocking mode
            // but log it for debugging
            ESP_LOGD(TAG, "Partial Noise frame: have %u, need %u",
                     (unsigned int)(tcp_buffer_len - consumed), (unsigned int)frame_total);
            break;
        }

        // Decrypt this Noise frame
        size_t decrypted_len = payload_len - 16;  // Minus 16-byte Poly1305 MAC
        if (payload_len < 16) {
            ESP_LOGW(TAG, "Noise frame too short: %d bytes", payload_len);
            consumed += frame_total;
            continue;
        }

        uint8_t *decrypted = malloc(decrypted_len);
        if (!decrypted) {
            ret = ESP_ERR_NO_MEM;
            break;
        }

        ret = noise_decrypt(ml->coordination.rx_key, ml->coordination.rx_nonce++,
                            NULL, 0, tcp_buffer + consumed + 3, payload_len, decrypted);

        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to decrypt long-poll Noise frame (nonce=%lu)",
                     (unsigned long)(ml->coordination.rx_nonce - 1));
            free(decrypted);
            break;
        }

        // Successfully decrypted - log the HTTP/2 frame info
        if (decrypted_len >= 9) {
            int h2_len = (decrypted[0] << 16) | (decrypted[1] << 8) | decrypted[2];
            int h2_type = decrypted[3];
            int h2_flags = decrypted[4];

            // Check if this looks like a valid HTTP/2 frame header
            // Note: H2 frames can span multiple Noise transport frames, so h2_len may be > decrypted_len
            bool valid_h2_header = (h2_type <= 0x09) && (h2_len <= 16777215);
            bool complete_h2_frame = ((size_t)(h2_len + 9) <= decrypted_len);

            if (!valid_h2_header) {
                // This is a continuation of a previous H2 frame (no valid header)
                // We still need to send WINDOW_UPDATE for the data we received!
                ESP_LOGD(TAG, "H2 continuation frame: decrypted_len=%u (no header), stream=%d",
                         (unsigned int)decrypted_len, last_partial_stream_id);

                // Send WINDOW_UPDATE for connection-level flow control
                int data_received = (decrypted_len > 0) ? decrypted_len : 0;
                if (data_received > 0) {
                    uint8_t window_update[13];
                    window_update[0] = 0x00;
                    window_update[1] = 0x00;
                    window_update[2] = 0x04;
                    window_update[3] = 0x08;  // WINDOW_UPDATE
                    window_update[4] = 0x00;
                    window_update[5] = 0x00;
                    window_update[6] = 0x00;
                    window_update[7] = 0x00;
                    window_update[8] = 0x00;  // Stream 0
                    window_update[9] = (data_received >> 24) & 0xFF;
                    window_update[10] = (data_received >> 16) & 0xFF;
                    window_update[11] = (data_received >> 8) & 0xFF;
                    window_update[12] = data_received & 0xFF;

                    size_t enc_len = sizeof(window_update) + 16;
                    uint8_t *enc_buf = malloc(3 + enc_len);
                    if (enc_buf) {
                        enc_buf[0] = 0x04;
                        enc_buf[1] = (enc_len >> 8) & 0xFF;
                        enc_buf[2] = enc_len & 0xFF;
                        esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                                          NULL, 0, window_update, sizeof(window_update), enc_buf + 3);
                        if (enc_ret == ESP_OK) {
                            int sent = send(sock, enc_buf, 3 + enc_len, 0);
                            ESP_LOGI(TAG, "Sent connection WINDOW_UPDATE +%d bytes (sent=%d)", data_received, sent);
                        }
                        free(enc_buf);
                    }

                    // Also send stream-level WINDOW_UPDATE if we have a saved stream ID
                    if (last_partial_stream_id > 0) {
                        window_update[5] = (last_partial_stream_id >> 24) & 0xFF;
                        window_update[6] = (last_partial_stream_id >> 16) & 0xFF;
                        window_update[7] = (last_partial_stream_id >> 8) & 0xFF;
                        window_update[8] = last_partial_stream_id & 0xFF;

                        enc_buf = malloc(3 + enc_len);
                        if (enc_buf) {
                            enc_buf[0] = 0x04;
                            enc_buf[1] = (enc_len >> 8) & 0xFF;
                            enc_buf[2] = enc_len & 0xFF;
                            esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                                              NULL, 0, window_update, sizeof(window_update), enc_buf + 3);
                            if (enc_ret == ESP_OK) {
                                int sent = send(sock, enc_buf, 3 + enc_len, 0);
                                ESP_LOGI(TAG, "Sent stream %d WINDOW_UPDATE +%d bytes (sent=%d)",
                                         last_partial_stream_id, data_received, sent);
                            }
                            free(enc_buf);
                        }
                    }
                }

                free(decrypted);
                consumed += frame_total;
                frames_processed++;
                continue;
            }

            // Valid H2 header but frame spans multiple Noise frames
            if (!complete_h2_frame) {
                ESP_LOGD(TAG, "Partial H2 %s frame: h2_len=%d decrypted_len=%u (spanning Noise frames)",
                         h2_type == 0x00 ? "DATA" : "OTHER", h2_len, (unsigned int)decrypted_len);
                // Still process what we can - fall through to handle partial data
            }

            const char *type_name =
                h2_type == 0x00 ? "DATA" :
                h2_type == 0x01 ? "HEADERS" :
                h2_type == 0x04 ? "SETTINGS" :
                h2_type == 0x06 ? "PING" :
                h2_type == 0x07 ? "GOAWAY" :
                h2_type == 0x08 ? "WINDOW_UPDATE" : "OTHER";

            ESP_LOGI(TAG, "Long-poll H2 frame: %s len=%d flags=0x%02x",
                     type_name, h2_len, h2_flags);

            // Log DATA frame content for debugging
            if (h2_type == 0x00 && h2_len > 0 && decrypted_len > 9) {
                // DATA payload starts at offset 9 in the decrypted buffer
                int log_len = (h2_len < 200) ? h2_len : 200;
                char log_buf[512];
                int log_pos = 0;
                for (int i = 0; i < log_len && i < (int)decrypted_len - 9; i++) {
                    char c = decrypted[9 + i];
                    if (c >= 32 && c < 127) {
                        log_buf[log_pos++] = c;
                    } else {
                        log_pos += snprintf(log_buf + log_pos, sizeof(log_buf) - log_pos, "\\x%02x", (uint8_t)c);
                    }
                    if (log_pos >= 450) break;
                }
                log_buf[log_pos] = '\0';
                ESP_LOGI(TAG, "Long-poll DATA content: %s", log_buf);
            }

            // Handle HTTP/2 DATA frames - send WINDOW_UPDATE to acknowledge
            // This is CRITICAL for HTTP/2 flow control! Without WINDOW_UPDATE,
            // the server's send window depletes and it closes the connection.
            if (h2_type == 0x00 && h2_len > 0) {
                // Extract stream ID from frame header
                int stream_id = (decrypted[5] << 24) | (decrypted[6] << 16) |
                                (decrypted[7] << 8) | decrypted[8];

                // Calculate actual data received in THIS Noise frame
                // For partial frames, use actual received bytes; for complete frames, use claimed length
                int actual_data_len;
                if (complete_h2_frame) {
                    actual_data_len = h2_len;  // Full frame received
                    last_partial_stream_id = 0;  // Clear - no continuation expected
                } else {
                    // Partial frame - use actual payload bytes received (decrypted_len - 9 byte H2 header)
                    actual_data_len = (decrypted_len > 9) ? (decrypted_len - 9) : 0;
                    // Save stream ID for continuation frame handling
                    last_partial_stream_id = stream_id;
                    ESP_LOGI(TAG, "Partial DATA frame: claimed=%d actual=%d stream=%d (will get rest in continuation)",
                             h2_len, actual_data_len, stream_id);
                }

                if (actual_data_len > 0) {
                    // Send WINDOW_UPDATE for both connection (stream 0) and the stream
                    // WINDOW_UPDATE format: 9-byte header + 4-byte window increment
                    uint8_t window_update[13];
                    window_update[0] = 0x00;  // Length high
                    window_update[1] = 0x00;  // Length mid
                    window_update[2] = 0x04;  // Length low (4 bytes)
                    window_update[3] = 0x08;  // Type: WINDOW_UPDATE
                    window_update[4] = 0x00;  // Flags: none
                    // Stream ID 0 = connection-level
                    window_update[5] = 0x00;
                    window_update[6] = 0x00;
                    window_update[7] = 0x00;
                    window_update[8] = 0x00;
                    // Window increment = ACTUAL received data length
                    window_update[9] = (actual_data_len >> 24) & 0xFF;
                    window_update[10] = (actual_data_len >> 16) & 0xFF;
                    window_update[11] = (actual_data_len >> 8) & 0xFF;
                    window_update[12] = actual_data_len & 0xFF;

                    // Encrypt and send connection-level WINDOW_UPDATE
                    size_t enc_len = sizeof(window_update) + 16;
                    uint8_t *enc_buf = malloc(3 + enc_len);
                    if (enc_buf) {
                        enc_buf[0] = 0x04;
                        enc_buf[1] = (enc_len >> 8) & 0xFF;
                        enc_buf[2] = enc_len & 0xFF;

                        esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                                          NULL, 0, window_update, sizeof(window_update), enc_buf + 3);
                        if (enc_ret == ESP_OK) {
                            int sent = send(sock, enc_buf, 3 + enc_len, 0);
                            ESP_LOGI(TAG, "Sent connection WINDOW_UPDATE +%d bytes (sent=%d)", actual_data_len, sent);
                        }
                        free(enc_buf);
                    }

                    // Also send stream-level WINDOW_UPDATE if stream_id > 0
                    if (stream_id > 0) {
                        window_update[5] = (stream_id >> 24) & 0xFF;
                        window_update[6] = (stream_id >> 16) & 0xFF;
                        window_update[7] = (stream_id >> 8) & 0xFF;
                        window_update[8] = stream_id & 0xFF;

                        enc_buf = malloc(3 + enc_len);
                        if (enc_buf) {
                            enc_buf[0] = 0x04;
                            enc_buf[1] = (enc_len >> 8) & 0xFF;
                            enc_buf[2] = enc_len & 0xFF;

                            esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                                              NULL, 0, window_update, sizeof(window_update), enc_buf + 3);
                            if (enc_ret == ESP_OK) {
                                int sent = send(sock, enc_buf, 3 + enc_len, 0);
                                ESP_LOGI(TAG, "Sent stream %d WINDOW_UPDATE +%d bytes (sent=%d)", stream_id, actual_data_len, sent);
                            }
                            free(enc_buf);
                        }
                    }
                }
            }

            // Handle HTTP/2 PING - respond with PONG (same payload, ACK flag set)
            if (h2_type == 0x06 && h2_len == 8 && !(h2_flags & 0x01)) {
                ESP_LOGI(TAG, "Received HTTP/2 PING, sending PONG");

                // Build HTTP/2 PONG frame (same payload, ACK flag=0x01)
                // Frame format: 3-byte length (8) + 1-byte type (0x06) + 1-byte flags (0x01) + 4-byte stream ID (0)
                uint8_t pong_frame[17];  // 9-byte header + 8-byte payload
                pong_frame[0] = 0x00;  // Length high byte
                pong_frame[1] = 0x00;  // Length mid byte
                pong_frame[2] = 0x08;  // Length low byte (8 bytes)
                pong_frame[3] = 0x06;  // Type: PING
                pong_frame[4] = 0x01;  // Flags: ACK
                pong_frame[5] = 0x00;  // Stream ID (always 0 for PING)
                pong_frame[6] = 0x00;
                pong_frame[7] = 0x00;
                pong_frame[8] = 0x00;
                // Copy the 8-byte ping payload for pong response
                if (decrypted_len >= 17) {
                    memcpy(pong_frame + 9, decrypted + 9, 8);
                } else {
                    memset(pong_frame + 9, 0, 8);  // Zero payload if somehow short
                }

                // Encrypt and send PONG
                size_t enc_len = sizeof(pong_frame) + 16;  // +16 for MAC
                uint8_t *enc_buf = malloc(3 + enc_len);
                if (enc_buf) {
                    enc_buf[0] = 0x04;  // Noise transport message
                    enc_buf[1] = (enc_len >> 8) & 0xFF;
                    enc_buf[2] = enc_len & 0xFF;

                    esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                                      NULL, 0, pong_frame, sizeof(pong_frame), enc_buf + 3);
                    if (enc_ret == ESP_OK) {
                        int sent = send(sock, enc_buf, 3 + enc_len, 0);
                        if (sent == 3 + enc_len) {
                            ESP_LOGI(TAG, "HTTP/2 PONG sent successfully");
                        } else {
                            ESP_LOGW(TAG, "Failed to send PONG: sent=%d", sent);
                        }
                    } else {
                        ESP_LOGE(TAG, "Failed to encrypt PONG");
                    }
                    free(enc_buf);
                }
            }
        }

        free(decrypted);
        frames_processed++;
        total_frames_processed++;
        consumed += frame_total;
    }

        // End of frame processing for this buffer iteration
        // If we processed frames, loop back to check for more data
        if (frames_processed > 0) {
            ESP_LOGD(TAG, "Drain iteration %d: processed %d frames, checking for more...",
                     drain_iterations, frames_processed);
        }
    }  // End of drain_loop while

cleanup:
    // Restore blocking mode
    fcntl(sock, F_SETFL, flags);
    free(tcp_buffer);

    if (total_frames_processed > 0) {
        ESP_LOGI(TAG, "Long-poll: processed %d Noise frames (drain iterations=%d)",
                 total_frames_processed, drain_iterations);
        ml->coordination.last_heartbeat_ms = microlink_get_time_ms();
    }

    return ret;
}

/**
 * @brief Force regeneration of machine keys
 *
 * WARNING: This will change the device identity and require re-authorization
 * in the Tailscale admin console.
 */
esp_err_t microlink_coordination_regenerate_machine_key(microlink_t *ml) {
    ESP_LOGW(TAG, "Regenerating machine key - device will need re-authorization!");

    // Clear existing key from NVS
    nvs_handle_t nvs;
    esp_err_t ret = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (ret == ESP_OK) {
        nvs_erase_key(nvs, NVS_KEY_MACHINE_PRI);
        nvs_erase_key(nvs, NVS_KEY_MACHINE_PUB);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG, "Erased old machine key from NVS");
    }

    // Generate new machine keypair
    esp_fill_random(ml->coordination.machine_private_key, 32);

    // Clamp to X25519 requirements (done by x25519 with clamp=1, but we do it explicitly for clarity)
    ml->coordination.machine_private_key[0] &= 248;
    ml->coordination.machine_private_key[31] &= 127;
    ml->coordination.machine_private_key[31] |= 64;

    // Derive public key using x25519 from wireguard-lwip
    // x25519(out, scalar, base, clamp) - clamp=0 since we already clamped
    static const uint8_t basepoint[32] = {9};
    x25519(ml->coordination.machine_public_key, ml->coordination.machine_private_key, basepoint, 0);

    // Save new key to NVS
    ret = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (ret == ESP_OK) {
        ret = nvs_set_blob(nvs, NVS_KEY_MACHINE_PRI, ml->coordination.machine_private_key, 32);
        if (ret == ESP_OK) {
            ret = nvs_set_blob(nvs, NVS_KEY_MACHINE_PUB, ml->coordination.machine_public_key, 32);
        }
        if (ret == ESP_OK) {
            nvs_commit(nvs);
            ESP_LOGI(TAG, "Saved new machine key to NVS");
        }
        nvs_close(nvs);
    }

    // Reset registration state
    ml->coordination.registered = false;
    ml->coordination.handshake_complete = false;

    // Update machine key string
    snprintf(ml->coordination.machine_key, sizeof(ml->coordination.machine_key),
             "mkey:%02x%02x%02x%02x",
             ml->coordination.machine_public_key[0],
             ml->coordination.machine_public_key[1],
             ml->coordination.machine_public_key[2],
             ml->coordination.machine_public_key[3]);

    ESP_LOGI(TAG, "New machine key: %s", ml->coordination.machine_key);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, ml->coordination.machine_public_key, 8, ESP_LOG_DEBUG);

    return ESP_OK;
}

/**
 * @brief Factory reset - erase ALL stored keys and credentials
 *
 * This function erases the entire "microlink" NVS namespace, clearing:
 * - Machine keys (ts2021 Noise protocol)
 * - WireGuard keys
 * - DISCO keys
 *
 * After calling this function, the device will generate new keys and
 * need to be re-authorized in the Tailscale admin console.
 *
 * Call this BEFORE microlink_init() on boot.
 */
esp_err_t microlink_factory_reset(void) {
    ESP_LOGW(TAG, "=== MICROLINK FACTORY RESET ===");
    ESP_LOGW(TAG, "Erasing ALL stored keys - device will need re-authorization!");

    nvs_handle_t nvs;
    esp_err_t ret = nvs_open("microlink", NVS_READWRITE, &nvs);
    if (ret == ESP_OK) {
        ret = nvs_erase_all(nvs);
        if (ret == ESP_OK) {
            ret = nvs_commit(nvs);
            ESP_LOGI(TAG, "Successfully erased all microlink NVS data");
        } else {
            ESP_LOGE(TAG, "Failed to erase NVS: %s", esp_err_to_name(ret));
        }
        nvs_close(nvs);
    } else {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(ret));
    }

    ESP_LOGW(TAG, "Factory reset complete - restart required");
    return ret;
}

/* ============================================================================
 * Dual-Core Coordination Polling Task (ECONNRESET Fix)
 *
 * This section implements the solution to the ECONNRESET problem:
 *
 * PROBLEM:
 * - The Tailscale server sends large MapResponses (22KB+)
 * - ESP32's TCP receive buffer is small (5744 bytes default)
 * - During DISCO/DERP operations (which block for ~65ms), the coordination
 *   socket is not being read
 * - TCP receive buffer fills, kernel can't ACK, server times out -> RST
 *
 * SOLUTION:
 * - Dedicated high-priority FreeRTOS task on Core 1
 * - Polls coordination socket at 100Hz (every 10ms)
 * - Uses 64KB buffer in PSRAM (not precious SRAM)
 * - Core 0 handles DISCO/DERP without blocking coordination
 *
 * This approach was inspired by the tailscale-iot project's architecture.
 * ========================================================================== */

/**
 * @brief Forward declaration for noise_decrypt (defined elsewhere in this file)
 */
static esp_err_t noise_decrypt(const uint8_t *key, uint64_t nonce,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *plaintext);

/**
 * @brief Forward declaration for noise_encrypt (defined elsewhere in this file)
 */
static esp_err_t noise_encrypt(const uint8_t *key, uint64_t nonce,
                               const uint8_t *ad, size_t ad_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *ciphertext);

/**
 * @brief Dedicated coordination polling task running on Core 1
 *
 * This task runs at highest priority and polls the coordination socket
 * continuously, preventing TCP buffer overflow and server timeouts.
 *
 * @param pvParameters Pointer to microlink_t context
 */
static void coordination_poll_task(void *pvParameters) {
    microlink_t *ml = (microlink_t *)pvParameters;
    ESP_LOGI(TAG, "Coordination poll task started on Core %d, rx_nonce=%lu, tx_nonce=%lu",
             xPortGetCoreID(), (unsigned long)ml->coordination.rx_nonce,
             (unsigned long)ml->coordination.tx_nonce);

    uint64_t last_ping_ms = 0;
    uint64_t last_log_ms = 0;
    uint32_t local_frames_processed = 0;
    int decrypt_fail_count = 0;  // Track consecutive decrypt failures

    // Persistent buffer state for handling partial frames across recv() calls
    // We use a dedicated portion of PSRAM buffer for the receive stream
    const size_t RECV_BUFFER_OFFSET = 1024;  // Start recv buffer at offset 1024
    const size_t RECV_BUFFER_SIZE = MICROLINK_COORD_BUFFER_SIZE - RECV_BUFFER_OFFSET - 256;  // Leave room for temp buffers
    size_t buffer_len = 0;  // Amount of valid data in buffer

    while (ml->coordination.poll_task_running) {
        uint64_t now_ms = microlink_get_time_ms();

        // Check if we have a valid socket and handshake is complete
        if (!ml->coordination.handshake_complete || ml->coordination.socket < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));  // Sleep longer when not connected
            continue;
        }

        // Try to acquire mutex with timeout (don't block forever)
        if (xSemaphoreTake(ml->coordination.mutex, pdMS_TO_TICKS(5)) != pdTRUE) {
            vTaskDelay(pdMS_TO_TICKS(1));
            continue;
        }

        int sock = ml->coordination.socket;
        if (sock < 0) {
            xSemaphoreGive(ml->coordination.mutex);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // Send HTTP/2 PING periodically to keep connection alive
        if (now_ms - last_ping_ms >= MICROLINK_COORD_PING_INTERVAL_MS) {
            uint8_t ping_frame[17];
            ping_frame[0] = 0x00;  // Length high
            ping_frame[1] = 0x00;  // Length mid
            ping_frame[2] = 0x08;  // Length low (8 bytes)
            ping_frame[3] = 0x06;  // Type: PING
            ping_frame[4] = 0x00;  // Flags: none
            ping_frame[5] = 0x00;  // Stream ID 0
            ping_frame[6] = 0x00;
            ping_frame[7] = 0x00;
            ping_frame[8] = 0x00;
            // Opaque payload
            uint64_t ping_id = now_ms;
            ping_frame[9] = (ping_id >> 56) & 0xFF;
            ping_frame[10] = (ping_id >> 48) & 0xFF;
            ping_frame[11] = (ping_id >> 40) & 0xFF;
            ping_frame[12] = (ping_id >> 32) & 0xFF;
            ping_frame[13] = (ping_id >> 24) & 0xFF;
            ping_frame[14] = (ping_id >> 16) & 0xFF;
            ping_frame[15] = (ping_id >> 8) & 0xFF;
            ping_frame[16] = ping_id & 0xFF;

            size_t enc_len = sizeof(ping_frame) + 16;
            uint8_t *enc_buf = ml->coordination.psram_buffer;  // Use PSRAM buffer

            enc_buf[0] = 0x04;
            enc_buf[1] = (enc_len >> 8) & 0xFF;
            enc_buf[2] = enc_len & 0xFF;

            esp_err_t enc_ret = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                              NULL, 0, ping_frame, sizeof(ping_frame), enc_buf + 3);
            if (enc_ret == ESP_OK) {
                int sent = send(sock, enc_buf, 3 + enc_len, MSG_DONTWAIT);
                if (sent == 3 + (int)enc_len) {
                    last_ping_ms = now_ms;
                    ESP_LOGD(TAG, "[Core1] Sent HTTP/2 PING");
                } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    ESP_LOGW(TAG, "[Core1] PING send failed: errno=%d", errno);
                }
            }
        }

        // Non-blocking read from socket using PSRAM buffer
        // Append new data after any unconsumed data from previous recv
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        uint8_t *buffer = ml->coordination.psram_buffer;
        uint8_t *recv_buffer = buffer + RECV_BUFFER_OFFSET;
        size_t space_available = RECV_BUFFER_SIZE - buffer_len;

        // Read new data into buffer after existing unconsumed data
        int recv_len = recv(sock, recv_buffer + buffer_len, space_available, 0);

        if (recv_len > 0) {
            size_t old_buffer_len = buffer_len;
            buffer_len += recv_len;

            // Log what we received for debugging
            ESP_LOGI(TAG, "[Core1] Recv %d bytes (buffer now %u), first 16: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
                     recv_len, (unsigned int)buffer_len,
                     recv_buffer[old_buffer_len+0], recv_buffer[old_buffer_len+1], recv_buffer[old_buffer_len+2], recv_buffer[old_buffer_len+3],
                     recv_buffer[old_buffer_len+4], recv_buffer[old_buffer_len+5], recv_buffer[old_buffer_len+6], recv_buffer[old_buffer_len+7],
                     recv_buffer[old_buffer_len+8], recv_buffer[old_buffer_len+9], recv_buffer[old_buffer_len+10], recv_buffer[old_buffer_len+11],
                     recv_buffer[old_buffer_len+12], recv_buffer[old_buffer_len+13], recv_buffer[old_buffer_len+14], recv_buffer[old_buffer_len+15]);

            // Process received Noise frames from the ENTIRE buffer (including leftover data)
            size_t consumed = 0;
            uint8_t *data = recv_buffer;

            while (consumed + 3 <= buffer_len) {
                if (data[consumed] != 0x04) {
                    ESP_LOGW(TAG, "[Core1] Non-0x04 byte at offset %u: 0x%02x", (unsigned int)consumed, data[consumed]);
                    consumed++;
                    continue;
                }

                int payload_len = (data[consumed + 1] << 8) | data[consumed + 2];
                if (consumed + 3 + payload_len > buffer_len) {
                    ESP_LOGD(TAG, "[Core1] Incomplete frame: need %d bytes, have %u",
                             3 + payload_len, (unsigned int)(buffer_len - consumed));
                    break;  // Incomplete frame - will get rest on next recv
                }

                if (payload_len < 16) {
                    ESP_LOGW(TAG, "[Core1] Frame too short: payload_len=%d (need >= 16 for MAC)", payload_len);
                    consumed += 3 + payload_len;
                    continue;
                }

                {
                    size_t decrypted_len = payload_len - 16;
                    uint8_t *decrypted = buffer + 128;  // Use offset 128-1024 for decryption output (before recv buffer at 1024)

                    // Try to decrypt with current nonce
                    uint64_t try_nonce = ml->coordination.rx_nonce;
                    esp_err_t dec_ret = noise_decrypt(ml->coordination.rx_key, try_nonce,
                                                      NULL, 0, data + consumed + 3, payload_len, decrypted);

                    if (dec_ret == ESP_OK) {
                        // Only increment nonce on successful decryption
                        ml->coordination.rx_nonce++;
                        local_frames_processed++;
                        decrypt_fail_count = 0;  // Reset on success

                        // Log successful frame processing for debugging
                        ESP_LOGI(TAG, "[Core1] Frame OK: nonce=%lu, decrypted_len=%u, rx_nonce now=%lu",
                                 (unsigned long)try_nonce, (unsigned int)decrypted_len,
                                 (unsigned long)ml->coordination.rx_nonce);

                        // Parse HTTP/2 frame and handle WINDOW_UPDATE if needed
                        if (decrypted_len >= 9) {
                            int h2_len = (decrypted[0] << 16) | (decrypted[1] << 8) | decrypted[2];
                            int h2_type = decrypted[3];
                            (void)h2_len;  // Suppress unused warning

                            // If DATA frame, send WINDOW_UPDATE to maintain flow control
                            if (h2_type == 0x00 && h2_len > 0) {
                                uint8_t window_update[13];
                                window_update[0] = 0x00;
                                window_update[1] = 0x00;
                                window_update[2] = 0x04;
                                window_update[3] = 0x08;  // WINDOW_UPDATE
                                window_update[4] = 0x00;
                                window_update[5] = 0x00;
                                window_update[6] = 0x00;
                                window_update[7] = 0x00;
                                window_update[8] = 0x00;  // Stream 0
                                window_update[9] = (decrypted_len >> 24) & 0xFF;
                                window_update[10] = (decrypted_len >> 16) & 0xFF;
                                window_update[11] = (decrypted_len >> 8) & 0xFF;
                                window_update[12] = decrypted_len & 0xFF;

                                size_t wu_enc_len = sizeof(window_update) + 16;
                                uint8_t *wu_buf = buffer + 64;  // Use offset 64-128 for WINDOW_UPDATE (before recv buffer)

                                wu_buf[0] = 0x04;
                                wu_buf[1] = (wu_enc_len >> 8) & 0xFF;
                                wu_buf[2] = wu_enc_len & 0xFF;

                                esp_err_t wu_enc = noise_encrypt(ml->coordination.tx_key, ml->coordination.tx_nonce++,
                                                                 NULL, 0, window_update, sizeof(window_update), wu_buf + 3);
                                if (wu_enc == ESP_OK) {
                                    send(sock, wu_buf, 3 + wu_enc_len, MSG_DONTWAIT);
                                }
                            }
                        }
                    } else {
                        // Decrypt failed - this is fatal for Noise protocol
                        // Once we're desync'd on nonces, all subsequent frames will fail
                        decrypt_fail_count++;
                        ESP_LOGW(TAG, "[Core1] Decrypt failed (count=%d) nonce=%lu, frame_len=%d, consumed=%u/%d",
                                 decrypt_fail_count, (unsigned long)try_nonce, payload_len,
                                 (unsigned int)consumed, recv_len);
                        ESP_LOGW(TAG, "[Core1] Frame bytes: %02x%02x%02x | %02x%02x%02x%02x %02x%02x%02x%02x",
                                 data[consumed], data[consumed+1], data[consumed+2],
                                 data[consumed+3], data[consumed+4], data[consumed+5], data[consumed+6],
                                 data[consumed+7], data[consumed+8], data[consumed+9], data[consumed+10]);

                        // On first decrypt failure, signal error - no point continuing
                        // Noise nonce desync is unrecoverable without reconnection
                        ESP_LOGE(TAG, "[Core1] Nonce desync detected, will reconnect");
                        ml->coordination.connection_error = true;
                        break;  // Exit frame processing loop
                    }
                }

                consumed += 3 + payload_len;
            }

            // Log summary of frame processing
            ESP_LOGI(TAG, "[Core1] Processed: consumed=%u/%u bytes, frames_ok=%lu",
                     (unsigned int)consumed, (unsigned int)buffer_len, (unsigned long)local_frames_processed);

            // Preserve unconsumed data for next recv
            if (consumed > 0 && consumed < buffer_len) {
                size_t remaining = buffer_len - consumed;
                memmove(recv_buffer, recv_buffer + consumed, remaining);
                buffer_len = remaining;
                ESP_LOGD(TAG, "[Core1] Preserved %u bytes of partial frame data", (unsigned int)remaining);
            } else if (consumed == buffer_len) {
                // All data consumed
                buffer_len = 0;
            }
            // If consumed == 0, we didn't process anything (probably waiting for more data)

            ml->coordination.frames_processed = local_frames_processed;

        } else if (recv_len == 0) {
            // Connection closed
            ESP_LOGW(TAG, "[Core1] Connection closed by server");
            ml->coordination.connection_error = true;
            fcntl(sock, F_SETFL, flags);
            xSemaphoreGive(ml->coordination.mutex);
            break;  // Exit loop - let Core 0 handle reconnection
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Real error (including ECONNRESET=104, ENOTCONN=128)
            ESP_LOGE(TAG, "[Core1] Fatal socket error: errno=%d, signaling reconnect", errno);
            ml->coordination.connection_error = true;
            fcntl(sock, F_SETFL, flags);
            xSemaphoreGive(ml->coordination.mutex);
            break;  // Exit loop - let Core 0 handle reconnection
        }

        // Restore socket flags
        fcntl(sock, F_SETFL, flags);

        xSemaphoreGive(ml->coordination.mutex);

        // Log stats periodically
        if (now_ms - last_log_ms >= 60000) {
            ESP_LOGI(TAG, "[Core1] Coordination task: %lu frames processed, running on Core %d",
                     (unsigned long)local_frames_processed, xPortGetCoreID());
            last_log_ms = now_ms;
        }

        // Short delay to prevent CPU hogging (100Hz polling)
        vTaskDelay(pdMS_TO_TICKS(MICROLINK_COORD_POLL_INTERVAL_MS));
    }

    ESP_LOGI(TAG, "Coordination poll task exiting");

    // Clear our own handle before exiting so stop_poll_task knows we're done
    // This must be done BEFORE vTaskDelete to avoid race condition
    ml->coordination.poll_task_handle = NULL;

    vTaskDelete(NULL);
}

/**
 * @brief Start the dedicated coordination polling task on Core 1
 *
 * This should be called after the coordination handshake is complete
 * and the long-poll MapRequest has been sent.
 *
 * @param ml MicroLink context
 * @return ESP_OK on success
 */
esp_err_t microlink_coordination_start_poll_task(microlink_t *ml) {
    if (ml->coordination.poll_task_handle != NULL) {
        ESP_LOGW(TAG, "Poll task already running");
        return ESP_OK;
    }

    if (ml->coordination.mutex == NULL) {
        ESP_LOGE(TAG, "Mutex not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    if (ml->coordination.psram_buffer == NULL) {
        ESP_LOGE(TAG, "PSRAM buffer not allocated");
        return ESP_ERR_INVALID_STATE;
    }

    ml->coordination.poll_task_running = true;
    ml->coordination.connection_error = false;
    ml->coordination.frames_processed = 0;

    // Create task pinned to Core 1 with highest priority
    BaseType_t ret = xTaskCreatePinnedToCore(
        coordination_poll_task,
        "coord_poll",
        MICROLINK_COORD_TASK_STACK,
        ml,
        MICROLINK_COORD_TASK_PRIORITY,
        &ml->coordination.poll_task_handle,
        MICROLINK_COORDINATION_CORE
    );

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create coordination poll task");
        ml->coordination.poll_task_running = false;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Started coordination poll task on Core %d (priority %d)",
             MICROLINK_COORDINATION_CORE, MICROLINK_COORD_TASK_PRIORITY);

    return ESP_OK;
}

/**
 * @brief Stop the coordination polling task
 *
 * @param ml MicroLink context
 * @return ESP_OK on success
 */
esp_err_t microlink_coordination_stop_poll_task(microlink_t *ml) {
    if (ml->coordination.poll_task_handle == NULL && !ml->coordination.poll_task_running) {
        return ESP_OK;  // Already stopped
    }

    ESP_LOGI(TAG, "Stopping coordination poll task...");

    // Signal task to stop
    ml->coordination.poll_task_running = false;

    // Wait for task to exit (with timeout)
    // The task will clear poll_task_handle before calling vTaskDelete(NULL)
    int wait_count = 0;
    while (ml->coordination.poll_task_handle != NULL && wait_count < 100) {
        vTaskDelay(pdMS_TO_TICKS(20));
        wait_count++;
    }

    // If task exited cleanly, handle should be NULL now
    if (ml->coordination.poll_task_handle == NULL) {
        ESP_LOGI(TAG, "Coordination poll task stopped cleanly");
    } else {
        // Task didn't exit in time - this shouldn't happen normally
        // Don't force delete as the task may be in the middle of cleanup
        ESP_LOGW(TAG, "Poll task did not exit in time, clearing handle (task may still be running briefly)");
        ml->coordination.poll_task_handle = NULL;
    }

    return ESP_OK;
}

/**
 * @brief Check if the poll task detected a connection error
 *
 * The main state machine should call this periodically and handle
 * reconnection if an error is detected.
 *
 * @param ml MicroLink context
 * @return true if error detected, false otherwise
 */
bool microlink_coordination_check_error(microlink_t *ml) {
    bool error = ml->coordination.connection_error;
    if (error) {
        // Clear the flag so it doesn't trigger repeatedly
        ml->coordination.connection_error = false;
    }
    return error;
}

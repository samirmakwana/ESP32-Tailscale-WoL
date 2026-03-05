# MicroLink v1.3.0 Release Notes

## Community Fork Integration & Custom Server Support

This release integrates improvements from community forks and adds support for custom coordination servers (Headscale/Ionscale).

### New Features

**Custom Coordination Server Support (Headscale/Ionscale)**
- Configure custom coordination servers via Kconfig menuconfig
- Automatic server public key fetch from `/key` endpoint - no manual key configuration required
- Full ts2021 protocol compatibility with Headscale and Ionscale

**Zero-Copy WireGuard Mode**
- Optional high-throughput mode using raw lwIP PCBs instead of BSD sockets
- Eliminates memory copies for video streaming (30fps+) and large file transfers
- Enable via `MICROLINK_ZERO_COPY_WG` in menuconfig
- Contributed by [dj-oyu](https://github.com/dj-oyu)

### Path Discovery Improvements

**Adaptive Probe Intervals** (from dj-oyu fork)
- 5 seconds when searching for direct path (using_derp=true)
- 30 seconds when direct path is established
- Reduces unnecessary DERP traffic and CPU load

**PONG Rate-Limiting** (from dj-oyu fork)
- Rate-limit PONGs to 1/5s per peer when path is stable
- Prevents PONG floods during rapid PING sequences

**Symmetric NAT Port Spray** (from dj-oyu fork)
- Probes ±8 ports around known peer port for symmetric NAT traversal
- Exploits sequential port allocation behavior of many NAT devices

**CallMeMaybe Endpoint Preservation** (from dj-oyu fork)
- Fixed bug where CMM endpoints overwrote coordination server endpoints
- CMM endpoints are now temporary probing targets only
- Preserves authoritative endpoint list from coordination server

### Bug Fixes

**WireGuard Peer Lookup Fix** (from GrieferPig fork)
- Prefer peers with valid keypairs when looking up by allowed IP
- Prevents handshake failures with stale peer references
- Critical fix for multi-peer scenarios

**Direct PING last_seen Fix**
- Direct PINGs now properly update peer's last_seen timestamp
- Fixes false "stale path" detection for active direct connections

**DERP Fallback on Stale Paths**
- Reset WireGuard endpoint when direct path goes stale
- Ensures proper fallback to DERP relay

### Hardware Support

- Added ESP32-P4 to supported hardware list (uses standard ESP-IDF APIs)

### RX/TX Behavior (from v1.2.0)

The asymmetric RX/TX behavior from v1.2.0 continues to provide reliable bidirectional communication:
- **TX (ESP32 → PC)**: Uses DERP relay (consistent, works through all NATs)
- **RX (PC → ESP32)**: Uses direct UDP path when available (lower latency)
- **Callback-based RX**: High-priority task handles packets for consistent low-latency responses

### Configuration Options

New Kconfig options in `Component config → MicroLink Configuration`:

| Option | Default | Description |
|--------|---------|-------------|
| `MICROLINK_ZERO_COPY_WG` | Off | High-throughput mode (raw lwIP PCB) |
| `MICROLINK_CUSTOM_COORD_SERVER` | Off | Enable custom coordination server |
| `MICROLINK_COORD_HOST` | controlplane.tailscale.com | Custom server hostname |
| `MICROLINK_COORD_PORT` | 443 | Custom server port |

### Acknowledgments

This release includes contributions from community forks:

- **[dj-oyu](https://github.com/dj-oyu)** - Zero-copy WireGuard receive mode, PONG rate-limiting, adaptive probe intervals, symmetric NAT port spray, and path discovery optimizations. Originally developed for high-throughput video streaming on RDK-X5 smart pet camera.

- **[GrieferPig](https://github.com/GrieferPig)** - WireGuard peer lookup fix to prefer peers with valid keypairs, preventing handshake failures with stale peer references.

### Files Changed

- `src/microlink_disco.c` - Adaptive intervals, CMM fix, port spray, PONG rate-limit
- `src/microlink_coordination.c` - Dynamic /key endpoint fetch
- `src/microlink_disco_zerocopy.c` - New zero-copy implementation
- `components/wireguard_lwip/src/wireguardif.c` - Peer lookup fix
- `CMakeLists.txt` - Conditional DISCO source selection
- `Kconfig` - Zero-copy and custom server options
- `README.md` - Updated documentation

### Upgrade Notes

This release is backward compatible. All existing configurations continue to work with default settings. New features are opt-in via Kconfig.

---

**Full Changelog**: v1.2.0...v1.3.0

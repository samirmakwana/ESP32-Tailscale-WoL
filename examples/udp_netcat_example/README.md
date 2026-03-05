# UDP Netcat Example - Bidirectional UDP over Tailscale

This example demonstrates bidirectional UDP communication over Tailscale VPN on ESP32, equivalent to using netcat on Linux.

## Initialization Time

**Boot to "READY FOR COMMUNICATION": ~50-60 seconds**

| Phase | Duration | Notes |
|-------|----------|-------|
| WiFi connection | 5-10s | Depends on AP |
| Tailscale coordination | 10-15s | TLS handshake + auth |
| Peer list fetch | 5-10s | MapRequest/MapResponse |
| DERP connection | 5-10s | WebSocket + TLS |
| WireGuard handshake wait | 2s | Hardcoded delay |
| UDP socket creation | <1s | Includes retry logic |

**Important:** Wait for the `*** READY FOR COMMUNICATION! ***` banner before sending data.

## Configuration

Edit `main/main.c` and update these values:

```c
#define WIFI_SSID          "YOUR_WIFI_SSID"
#define WIFI_PASSWORD      "YOUR_WIFI_PASSWORD"
#define TAILSCALE_AUTH_KEY "tskey-auth-XXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#define TARGET_PEER_IP     "100.x.x.x"  /* Your PC's Tailscale IP */
```

### Getting a Tailscale Auth Key

1. Go to https://login.tailscale.com/admin/settings/keys
2. Generate an auth key (reusable recommended for development)
3. Copy the `tskey-auth-...` value

### Finding Your PC's Tailscale IP

```bash
tailscale ip -4
```

## Building and Flashing

```bash
# Set up ESP-IDF environment
. $IDF_PATH/export.sh

# Build
idf.py build

# Flash and monitor
idf.py -p /dev/ttyUSB0 flash monitor
```

## Testing Instructions

### Test 1: ESP32 → PC (Receive from ESP32)

On your PC, start a UDP listener:
```bash
nc -u -l 9000
```

The ESP32 sends "Hello from ESP32! count=X" every 30 seconds. You should see these messages appear in netcat.

### Test 2: PC → ESP32 (Send to ESP32)

Find your ESP32's Tailscale IP from the boot logs or run:
```bash
tailscale status | grep esp32
```

Send a message from your PC:
```bash
echo -n "test from PC" | nc -u <ESP32_TAILSCALE_IP> 9000
```

The ESP32 will print:
```
##  DATA: "test from PC"
```

And echo back with `ECHO: test from PC` (if ECHO_MODE_ENABLED is set).

### Test 3: Round-Trip Latency

With echo mode enabled, you can test round-trip latency:
```bash
# On PC, start listener first
nc -u -l 9000 &

# Send message and wait for echo
echo -n "ping" | nc -u <ESP32_TAILSCALE_IP> 9000
```

## Expected Output

### ESP32 Serial Output
```
*** READY FOR COMMUNICATION! ***

UDP socket listening on port 9000 - you can now send/receive!

================================================================================
                           TEST INSTRUCTIONS
================================================================================

  TO RECEIVE FROM ESP32 (run on PC 100.x.x.x):
    nc -u -l 9000

  TO SEND TO ESP32 (from any Tailscale peer):
    echo -n "test" | nc -u <ESP32_IP> 9000

================================================================================

[TX] Sent 25 bytes to 100.x.x.x:9000
[RX] UDP callback - 12 bytes from 100.x.x.x:12345
##  DATA: "test from PC"
[ECHO] Echoing back 18 bytes
```

### PC Output (netcat)
```
Hello from ESP32! count=1
Hello from ESP32! count=2
ECHO: test from PC
```

## Troubleshooting

### "MicroLink not connected" error
The example has retry logic. If it persists:
- Check WiFi credentials
- Verify Tailscale auth key is valid
- Ensure the ESP32 is approved in your Tailscale admin console

### No messages received
- Verify both devices are on the same Tailscale network
- Check `tailscale status` on your PC to see connected peers
- Try `tailscale ping esp32` to verify connectivity

### High latency or timeouts
- Direct UDP path may not be established yet
- Wait for DISCO ping/pong to complete (check logs for "PONG peer X direct")
- Some traffic may route via DERP relay initially

## Architecture Notes

This example uses:
- **MicroLink UDP API**: High-level UDP socket abstraction over WireGuard
- **Callback-based RX**: Packets handled by high-priority task for low latency
- **Echo mode**: Demonstrates bidirectional communication in a single session

The WireGuard tunnel is established automatically through Tailscale coordination.

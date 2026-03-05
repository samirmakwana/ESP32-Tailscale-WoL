ESP32-based Tailscale VPN Gateway with Wake-on-LAN capabilities based on MicroLink project. You need Tailscale account and Auth Keys from there to use it. 

## Changes from MicroLink
1. DISCO port conflict (microlink_disco.c): Changed DISCO socket binding from port 51820 to 51821 since WireGuard occupies the port 51820 which causes DISCO to fail.
2. Heartbeat reconnection loop (microlink_coordination.c): Forced it to always skip by changing the condition to 'if (1)' otherwise Tailscale drops connection after 2s.
3. STUN timeout (microlink_stun.c): Increased STUN_TIMEOUT_MS from 3000ms to 6000ms to allow enough time for actual UDP exchange.

## Requirements (Tested On)
- ESP-IDF v5.3
- ESP32-S3 with PSRAM (tested on ESP32-S3-N16R8, 16MB Flash, 8MB PSRAM)
- Tailscale account with a reusable auth key

## Configuration
Edit `main/main.c` and update:
- `WIFI_SSID` — your WiFi network name
- `WIFI_PASSWORD` — your WiFi password
- `TS_AUTH_KEY` — your Tailscale reusable auth key
- `LAN_BROADCAST` — your LAN broadcast address (default: 192.168.1.255)

## Build
```bash
# Replace /dev/tty.usbmodem1101 with your system's port
# macOS: /dev/tty.usbmodem* or /dev/tty.usbserial*
# Linux: /dev/ttyUSB0 or /dev/ttyACM0
# Windows: COM3 (check Device Manager)
source ~/esp/esp-idf/export.sh
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/tty.usbmodem1101 flash monitor
```

## SSH command
```bash
ssh -J <ESP32-name> username@target-machine-ip
```

## Wake-on-LAN command
```bash
curl "http://<ESP32-Tailscale-IP>/wol?mac=AA:BB:CC:DD:EE:FF"
```

## Credits
Based on [MicroLink by CamM2325](https://github.com/CamM2325/microlink)
Licensed under MIT License





## Requirements
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




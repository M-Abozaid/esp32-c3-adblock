#!/usr/bin/env bash
# Restore the ESP8266 adblock device from a cold start: flash the firmware,
# flash the filesystem image (blocklist + config), then reset the chip so it
# mounts the image it just received.
#
#   tools/restore_device.sh [PORT] [ENV]
#
#   PORT  serial port of the board   (default /dev/cu.usbserial-1440)
#   ENV   PlatformIO environment      (default esp8266)
#
# The order matters. The firmware moves the filesystem (1 MB -> 2 MB), so the
# chip has to be running the new firmware before the filesystem image is
# written, and the image has to be written before the final reset.
#
# Build order matters too: PlatformIO's `buildfs` target produces only the
# filesystem image and leaves no firmware.bin behind, so build the image first,
# then the program.
#
# Flash geometry (eagle.flash.4m2m.ld, 4 MB module):
#   app     0x40200000  1,044,464 B   (OTA slot 0x402FEFF0..0x40400000)
#   FS      0x40400000  2,072,576 B   (mounted size == littlefs.bin size)
#   EEPROM  0x405FB000  64 KB         (WiFi creds — neither flash touches it)
#
# Bootloader mode: hold FLASH (GPIO0), tap RESET, release FLASH. esptool also
# drives DTR/RTS, so on a board with the usual auto-reset circuit you do not
# have to touch anything.
set -euo pipefail

PORT="${1:-${ESP_PORT:-/dev/cu.usbserial-1440}}"
ENV_NAME="${2:-esp8266}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIO="${PIO:-/Users/thiensubs/Documents/KIMI_NIM/.pio-venv/bin/pio}"
PY="${PY:-/Users/thiensubs/Documents/KIMI_NIM/.pio-venv/bin/python}"
ESPTOOL="${ESPTOOL:-$HOME/.platformio/packages/tool-esptoolpy/esptool.py}"

cd "$ROOT"

[ -x "$PIO" ] || { echo "platformio not found: $PIO" >&2; exit 1; }
[ -e "$PORT" ] || { echo "serial port not found: $PORT" >&2; exit 1; }

echo "==> building filesystem image + firmware ($ENV_NAME)"
"$PIO" run -e "$ENV_NAME" -t buildfs
"$PIO" run -e "$ENV_NAME"

echo "==> flashing firmware to $PORT"
"$PIO" run -e "$ENV_NAME" -t upload --upload-port "$PORT"

echo "==> flashing filesystem image to $PORT"
"$PIO" run -e "$ENV_NAME" -t uploadfs --upload-port "$PORT"

echo "==> resetting the chip so it mounts the new filesystem"
"$PY" "$ESPTOOL" --port "$PORT" chip_id >/dev/null

echo
echo "==> done. Check it with: tools/verify_device.sh"

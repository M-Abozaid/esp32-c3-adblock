#!/usr/bin/env bash
# Regenerate the browser web-installer assets (docs/*.bin + manifest.json).
#
# Why this exists: the installer assets are prebuilt binaries, so they silently rot
# whenever the firmware or the partition table changes. The committed docs/*.bin
# dated back to the original web-installer commit (Jul 2026) and still contained a
# firmware from BEFORE the auth/CSRF hardening landed — anyone flashing through the
# browser installer today gets a device whose /upload, /update and /forgetwifi are
# unauthenticated. Run this script after touching main.cpp / page.h / partitions.csv
# and commit the results together with the change.
#
# Usage: tools/build_web_installer.sh     (requires pio; writes into docs/)
set -euo pipefail
cd "$(dirname "$0")/.."

# data/blocklist.bin is gitignored but the installer's littlefs image must embed a
# list — a device flashed with an empty list forwards everything until configured.
if [ ! -s data/blocklist.bin ]; then
  python3 tools/build_blocklist.py data/blocklist.bin
fi

pio run -e c3               # firmware.bin / bootloader.bin / partitions.bin
pio run -e c3 -t buildfs    # littlefs.bin (packaged from data/)

B=.pio/build/c3
for f in bootloader.bin partitions.bin firmware.bin littlefs.bin; do
  test -s "$B/$f" || { echo "error: $B/$f missing" >&2; exit 1; }
  cp "$B/$f" "docs/$f"
done
# Classic-ESP32 toolchains emit boot_app0.bin (an otadata bootstrap image); the C3
# build does not. It is a static template that never goes stale, so when the build
# doesn't provide one, keep the copy already in docs/ if present.
BOOT_APP0=""
if [ -s "$B/boot_app0.bin" ]; then
  cp "$B/boot_app0.bin" docs/boot_app0.bin
  BOOT_APP0="yes"
elif [ -s docs/boot_app0.bin ]; then
  BOOT_APP0="yes"
fi
export BOOT_APP0

# Parse the offsets for manifest.json straight from the just-built partitions.bin
# instead of hand-copying them — a hand-copied offset from an older partition table
# is exactly how the assets rotted in the first place.
python3 - "$B/partitions.bin" <<'EOF'
import json, os, struct, sys

parts = {}
data = open(sys.argv[1], 'rb').read()
for i in range(0, len(data), 32):
    e = data[i:i + 32]
    if e[:2] != b'\xaaP':
        continue
    ptype, sub = e[2], e[3]
    off, size = struct.unpack('<II', e[4:12])
    label = e[12:28].rstrip(b'\x00').decode()
    parts[label] = (ptype, sub, off, size)

app0, spiffs = parts['app0'], parts['spiffs']
assert app0[0] == 0, f"app0 is not an app partition: {app0}"
assert spiffs[0] == 1, f"spiffs is not a data partition: {spiffs}"
assert app0[2] + app0[3] <= spiffs[2], "app0 overlaps spiffs?!"

part_list = [
    {"path": "bootloader.bin", "offset": 0},
    {"path": "partitions.bin", "offset": 32768},
]
if os.environ.get("BOOT_APP0"):
    part_list.append({"path": "boot_app0.bin", "offset": 57344})
part_list += [
    {"path": "firmware.bin", "offset": app0[2]},
    {"path": "littlefs.bin", "offset": spiffs[2]},
]

manifest = {
    "name": "C3 AdBlocker",
    "version": "1.0.0",
    "new_install_prompt_erase": True,
    "builds": [{"chipFamily": "ESP32-C3", "parts": part_list}],
}
with open('docs/manifest.json', 'w') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
print(f"manifest.json: firmware @ {app0[2]:#x} (slot {app0[3]:#x}B), "
      f"littlefs @ {spiffs[2]:#x} ({spiffs[3]:#x}B)")
EOF

echo "done: docs/ installer assets rebuilt — commit them together with your change"

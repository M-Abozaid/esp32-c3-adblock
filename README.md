# esp32-c3-adblock

A **Pi-hole-style DNS ad-blocker** that runs on a **$2 ESP32-C3** — *no PSRAM required*.

The trick everyone misses: you don't need to keep the blocklist in RAM. Store the
domains as **sorted 64-bit hashes in flash** and binary-search them. 130,000+ domains
fit in ~1 MB of flash and are matched in microseconds, using **~40 KB of RAM**.

```
query in ──▶ extract domain ──▶ FNV-1a hash (+ parent suffixes)
         ──▶ binary-search the flash hash table
              ├─ hit  ──▶ answer 0.0.0.0   (sinkholed)
              └─ miss ──▶ forward to upstream resolver, relay the reply
```

## Why this is interesting

Most ESP32 DNS sinkholes load the blocklist (domain *strings*) into RAM, so they
demand an ESP32-S3 with 4–8 MB of **PSRAM**. This project stores fixed **8-byte
hashes in flash** instead:

| | string-in-RAM approach | this (hash-in-flash) |
|---|---|---|
| Hardware | ESP32-S3 + 8 MB PSRAM (~$8) | ESP32-C3, no PSRAM (~$2) |
| 130k domains | several MB of RAM | **1.02 MB of flash** |
| RAM used | most of it | **~40 KB** |
| Lookup | string compare | ~17 cached-flash reads (µs) |
| Collisions | n/a | 0 (64-bit hash) |

## Hardware

- Any **ESP32-C3** board (tested on a C3 SuperMini), 4 MB flash, **no PSRAM needed**
- Power it from a **stable USB source** (a phone charger or your router's USB port).
  Cheap/loose USB-C→A adapters can brown out the radio during WiFi transmit.

## Build & flash (PlatformIO)

```bash
# 1. generate the blocklist hash table (downloads StevenBlack hosts by default)
python3 tools/build_blocklist.py --download data/blocklist.bin
#    or a bigger list:
#    curl -sL https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts -o hosts
#    python3 tools/build_blocklist.py hosts data/blocklist.bin

# 2. set your WiFi creds (secrets.h is gitignored, so they stay local)
cp src/secrets.example.h src/secrets.h
#    then edit src/secrets.h -> WIFI_SSID / WIFI_PASS

# 3. flash firmware + the blocklist filesystem
pio run -t upload
pio run -t uploadfs

# 4. watch it boot
pio device monitor
```

You should see:
```
blocklist: 133267 domains (1066136 bytes)
WiFi up: 192.168.1.x
DNS sinkhole listening on :53
```

## Use it

Point a device's DNS at the C3's IP, or add it as a **secondary resolver** behind
your main DNS. Test:

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  (blocked)
dig @<c3-ip> github.com        # -> real IP  (forwarded)
```

## Gotchas (learned the hard way)

- **ModemManager** (default on Fedora/Ubuntu) grabs `/dev/ttyACM0` and toggles
  DTR/RTS, which **resets the C3** and blocks serial. Fix:
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- The C3's USB-Serial-JTAG console can swallow early boot output until the host
  connects (`while(!Serial)` helps).
- DNS clients add an **EDNS OPT** record; a blocked reply must contain only the
  question + answer (ANCOUNT=1, NSCOUNT=ARCOUNT=0) or it's malformed.

## How it could grow

- Bloom filter in RAM as a fast pre-filter (skip flash for the ~99% of misses)
- Repartition for ~300k domains
- Tiny web UI with block/allow counters
- mDNS hostname for easy discovery

## Credits

Inspired by [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — the
"answer 0.0.0.0 for blocklisted domains" idea. This is an independent from-scratch
implementation focused on the hash-in-flash optimization for PSRAM-less chips.

## License

MIT — see [LICENSE](LICENSE).

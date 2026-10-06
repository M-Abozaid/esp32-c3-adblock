#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a versioned, sorted truncated-FNV-1a
hash blob for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched
on the device, so no PSRAM is needed.

Output format (16-byte header, little-endian, then the payload):

  offset  size  field
  0       4     magic 'C3BL'
  4       1     format version (=1)
  5       1     hash bytes (must match the firmware)
  6       2     reserved (0)
  8       4     entry count
  12      4     CRC32 (IEEE) of the payload
  16      n*HB  sorted hashes

The header carries a version and a CRC32. This lets the firmware reject a random
blob and lets the format change later (prefix/suffix buckets, other codecs)
without mixing old and new .bin files.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [--format v1|raw] [--allow-missing] [out.bin] [src ...]
  --format v1  (default) writes the versioned container (magic + version + CRC32).
  --format raw writes the legacy headerless payload only. Keep it for older
               firmware that cannot read the container.
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Light) ~= 100k entries: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt
"""
import re
import sys, os, math, struct, zlib, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Container header. Keep MAGIC / FORMAT_VERSION / layout in sync with src/main.cpp.
MAGIC          = b'C3BL'
FORMAT_VERSION = 1
HEADER_SIZE    = 16

def header(count: int, payload: bytes) -> bytes:
    crc = zlib.crc32(payload) & 0xffffffff
    return MAGIC + struct.pack('<BBHII', FORMAT_VERSION, HASH_BYTES, 0, count, crc)


# Daily driver for the dual-OTA partition (weekly release limit: 600,000 bytes):
# ads + trackers + malware, WhatsApp/social keep working. ~100k entries / 0.5 MB
# (Hagezi's wildcard lists drop subdomains the firmware's parent-matching already covers).
# Want more? swap light-onlydomains.txt -> pro-onlydomains.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',  # Hagezi Light (wildcard = domain + subdomains)
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def main():
    global ALLOW_MISSING
    argv = sys.argv[1:]
    fmt = 'v1'
    if '--format' in argv:
        i = argv.index('--format')
        if i + 1 >= len(argv):
            sys.exit('--format needs a value: v1 or raw')
        fmt = argv[i + 1]
        del argv[i:i + 2]
    if fmt not in ('v1', 'raw'):
        sys.exit('--format must be v1 or raw')
    ALLOW_MISSING = '--allow-missing' in argv
    args = [a for a in argv if a != '--allow-missing']
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    payload = b''.join(h.to_bytes(HASH_BYTES, 'little') for h in uniq)
    blob = payload if fmt == 'raw' else header(len(uniq), payload) + payload
    with open(out, 'wb') as f:
        f.write(blob)

    n = len(uniq)
    payload_size = n * HASH_BYTES
    total = len(blob)
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    if fmt == 'raw':
        print(f'format           : legacy raw (no header) -- for older firmware')
    else:
        print(f'container        : v{FORMAT_VERSION}, {HEADER_SIZE}-byte header + {payload_size:,} B payload = {total:,} B')
    print(f'flash blob       : {total:,} bytes  ({total/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()

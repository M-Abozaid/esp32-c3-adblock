#!/usr/bin/env python3
"""Preprocess a hosts-format blocklist into a sorted 64-bit FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on
the device, so no PSRAM is needed. The same FNV-1a must run on the C3 firmware.

Usage: build_blocklist.py [hosts-file|--download] [out.bin]
"""
import sys, struct, os, math, urllib.request

FNV64_OFFSET = 0xcbf29ce484222325
FNV64_PRIME  = 0x100000001b3
MASK = (1 << 64) - 1

def fnv1a64(b: bytes) -> int:
    h = FNV64_OFFSET
    for c in b:
        h = ((h ^ c) * FNV64_PRIME) & MASK
    return h

def normalize(d: str) -> str:
    d = d.strip().lower().rstrip('.')
    return d[4:] if d.startswith('www.') else d

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else '--download'
    out = sys.argv[2] if len(sys.argv) > 2 else 'blocklist.bin'
    if src != '--download' and os.path.exists(src):
        data = open(src, errors='ignore').read()
    else:
        url = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
        print(f'downloading {url} ...', file=sys.stderr)
        data = urllib.request.urlopen(url, timeout=90).read().decode('utf-8', 'ignore')

    domains = set()
    for line in data.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        dom = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::') \
              else parts[0] if len(parts) == 1 else None
        if dom:
            dom = normalize(dom)
            if '.' in dom and ' ' not in dom:
                domains.add(dom)

    hashes = sorted(fnv1a64(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    with open(out, 'wb') as f:
        for h in hashes:
            f.write(struct.pack('<Q', h))

    n, size = len(hashes), len(hashes) * 8
    p = 0.01
    m = int(-n * math.log(p) / (math.log(2) ** 2))
    k = max(1, round(m / n * math.log(2)))
    print(f'domains          : {n:,}')
    print(f'hash collisions  : {collisions}  (each = one over-block; want 0)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'C3 flash budget  : 4 MB total, ~2.5 MB free after firmware -> fits: {"YES" if size < 2_500_000 else "TIGHT"}')
    print(f'lookup           : binary search, ~{math.ceil(math.log2(max(n,2)))} cached-flash reads/query')
    print(f'optional RAM bloom (1% FP): {m//8:,} bytes (~{m/8/1024:.0f} KB), k={k}  [skips flash for ~99% of queries]')

if __name__ == '__main__':
    main()

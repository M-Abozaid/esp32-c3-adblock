#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [--preset NAME] [src ...] [--allow-missing]
                          [--max-bytes N | --partitions FILE]
  src = local file or URL. With no src and no --preset, uses the 'default' preset.
  With --preset, the preset's sources are used and any src given is added to them.

  Presets:
    default   StevenBlack base + Hagezi Light, ~100k entries: blocks ads/trackers/malware
              but leaves WhatsApp/Instagram/social/messaging working.
    threats   Hagezi Threat Intelligence Feeds (mini): malware, phishing, scam, spam.
              Security only, no ad blocking. ~236k entries as of Oct 2026.
    security  Hagezi Light + TIF mini: ads/trackers plus threats. ~291k entries as of
              Oct 2026, which does NOT fit the stock dual-OTA filesystem partition;
              needs a larger filesystem partition (see README).

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt

Size check: the output must fit the device's LittleFS partition, because the firmware
deletes the old list before writing the new one. An upload that doesn't fit leaves the
device with no list (or a truncated one). The budget is read from ../partitions.csv
(the spiffs/littlefs data partition, minus FS_HEADROOM) and the build refuses to write
an output that exceeds it (exit code 3). Override with --max-bytes or --partitions.
"""
import argparse
import math
import os
import pathlib
import re
import sys
import tempfile
import urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

STEVENBLACK = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
HAGEZI_LIGHT = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt'
HAGEZI_TIF_MINI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt'

# 'default' is the daily driver that FITS alongside dual-OTA firmware slots (~260k entry budget):
# ads + trackers + malware, WhatsApp/social keep working. ~100k entries / 0.5 MB
# (Hagezi's wildcard lists drop subdomains the firmware's parent-matching already covers).
# Want more? swap light-onlydomains.txt -> pro-onlydomains.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
PRESETS = {
    'default':  [STEVENBLACK, HAGEZI_LIGHT],
    'threats':  [HAGEZI_TIF_MINI],
    'security': [HAGEZI_LIGHT, HAGEZI_TIF_MINI],
}
DEFAULT_SOURCES = PRESETS['default']    # kept for anything importing the old name

# Space LittleFS needs beyond the list itself: metadata, the dashboard's small state files
# (custom.txt, banned.txt, update.cfg) and allocator slack. Measured with littlefs-python on
# the stock 1.3125 MB partition (4 KiB blocks, 128-byte read/prog/cache/lookahead, writes in
# HTTP-upload-sized chunks): the largest list that fit was 1,339,788 bytes with worst-case
# state files present, i.e. ~36 KiB of overhead. 64 KiB leaves margin on top of that.
FS_HEADROOM = 64 * 1024
DEFAULT_PARTITIONS = pathlib.Path(__file__).resolve().parent.parent / 'partitions.csv'

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)


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


def parse_size(text: str) -> int:
    """Partition-table size field: 0x150000, 1376256, 1344K or 1M (ESP-IDF syntax)."""
    t = text.strip().upper()
    if t.startswith('0X'):
        return int(t, 16)
    if t.endswith('K'):
        return int(t[:-1]) * 1024
    if t.endswith('M'):
        return int(t[:-1]) * 1024 * 1024
    return int(t)


def fs_partition_size(csv_path) -> int:
    """Size in bytes of the spiffs/littlefs data partition in an ESP-IDF partition table."""
    for raw in pathlib.Path(csv_path).read_text().splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(',')]
        if len(fields) >= 5 and fields[1] == 'data' and fields[2] in ('spiffs', 'littlefs'):
            return parse_size(fields[4])
    raise ValueError(f'no spiffs/littlefs data partition in {csv_path}')


def size_budget(max_bytes, partitions):
    """(budget_bytes, description) or (None, reason) when no check can be made."""
    if max_bytes is not None:
        return max_bytes, '--max-bytes'
    path = pathlib.Path(partitions) if partitions else DEFAULT_PARTITIONS
    try:
        part = fs_partition_size(path)
    except (OSError, ValueError) as e:
        if partitions:                    # asked for explicitly: a typo must not disable the check
            raise SystemExit(f'  !! cannot size against {path}: {e}')
        return None, f'size check skipped: {e}'
    return part - FS_HEADROOM, f'{path.name}: {part:,}-byte filesystem minus {FS_HEADROOM // 1024} KiB headroom'


def collect(sources, allow_missing=False):
    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not allow_missing: sys.exit(1)
            continue
        for line in data.splitlines():
            s = line.strip()
            if s.startswith(('||', '@@')):
                line = s                   # AdGuard/ABP syntax: never treat as hosts comment
            elif not s.startswith('#') and ('##' in s or '#@#' in s or '#?#' in s or '#%#' in s):
                skipped += 1; continue    # cosmetic rule (baidu.com##div.ad) — the old
                                          # split('#') heuristic ate '##' and added the
                                          # bare domain (baidu.com!) to the blocklist
            else:
                line = s.split('#', 1)[0].strip()
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
    return domains, allow, skipped


def parse_args(argv):
    p = argparse.ArgumentParser(description='Build the device blocklist hash blob.')
    p.add_argument('out', nargs='?', default='blocklist.bin', help='output file (default blocklist.bin)')
    p.add_argument('sources', nargs='*', help='URLs or local files')
    p.add_argument('--preset', choices=sorted(PRESETS), help='named source set; extra sources are added to it')
    p.add_argument('--allow-missing', action='store_true', help='continue if a source cannot be read')
    p.add_argument('--max-bytes', type=int, help='explicit output size limit in bytes (overrides partitions.csv)')
    p.add_argument('--partitions', help='partition table to size against (default: ../partitions.csv)')
    return p.parse_intermixed_args(argv)


def main(argv=None):
    a = parse_args(sys.argv[1:] if argv is None else argv)
    if a.preset:
        sources = PRESETS[a.preset] + a.sources
    else:
        sources = a.sources or PRESETS['default']

    domains, allow, skipped = collect(sources, a.allow_missing)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    n, size = len(uniq), len(uniq) * HASH_BYTES

    budget, why = size_budget(a.max_bytes, a.partitions)
    if budget is None:
        print(f'  !! {why}', file=sys.stderr)
    elif size > budget:
        over = size - budget
        print(f'  !! TOO BIG for the device: {size:,} bytes ({n:,} entries) > budget {budget:,} bytes ({why}).\n'
              f'     Over by {over:,} bytes (~{math.ceil(over / HASH_BYTES):,} entries). Nothing written to {a.out}.\n'
              f'     The firmware deletes the old list before storing the new one, so uploading this\n'
              f'     would leave the device unprotected. Use fewer/smaller sources, or a partition\n'
              f'     table with a bigger filesystem (then point --partitions at it).', file=sys.stderr)
        sys.exit(3)

    # write atomically so a failed run never leaves a half-written blocklist behind
    out_dir = os.path.dirname(os.path.abspath(a.out))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix='.blocklist-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as f:
            for h in uniq:
                f.write(h.to_bytes(HASH_BYTES, 'little'))
        os.replace(tmp, a.out)
    except BaseException:
        os.unlink(tmp)
        raise

    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {a.out}')
    if budget is not None:
        print(f'device budget    : {budget:,} bytes, {100 * size / budget:.0f}% used  ({why})')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')


if __name__ == '__main__':
    main()

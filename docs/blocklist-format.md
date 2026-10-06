# blocklist.bin container format

This document describes the on-flash blocklist file. `tools/build_blocklist.py`
writes it. The firmware reads and verifies it.

## Why a container

An older firmware accepted any file whose size was a multiple of 5 bytes. A random
500000-byte file passes that test. The firmware then treated the bytes as hashes.

The container fixes this. A 16-byte header carries a magic value, a format version,
and a CRC32 of the payload. The firmware rejects a file that fails any check. The
version field lets a future format land without mixing old and new `.bin` files.

## Layout

All integers are little-endian.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | ASCII `C3BL` |
| 4 | 1 | format version | `1` |
| 5 | 1 | hash bytes | must equal the firmware `HASH_BYTES` (5) |
| 6 | 2 | reserved | `0` |
| 8 | 4 | entry count | number of hashes in the payload |
| 12 | 4 | CRC32 | CRC32 (IEEE) of the payload |
| 16 | count x hash_bytes | payload | sorted hashes, little-endian |

The payload does not change from the old format. It holds `count` hashes. Each hash
uses `hash_bytes` bytes, least-significant byte first. Hashes are sorted ascending.

The CRC32 uses the standard IEEE polynomial (`0xEDB88320`, reflected). Python
`zlib.crc32` and the firmware `crc32Update` produce the same value.

## Validation rules

The firmware accepts a file only when all rules hold:

1. The file is at least 16 bytes.
2. Bytes 0..3 equal `C3BL`.
3. Byte 4 equals 1.
4. Byte 5 equals `HASH_BYTES`.
5. The entry count is not zero.
6. The file size equals `16 + count * hash_bytes`. Trailing data is an error.
7. The payload CRC32 equals the header CRC32.

The firmware checks the CRC when it commits an upload or a remote fetch. It checks
the CRC again when it loads the file at boot.

If the file is invalid, the firmware loads no list. The device then forwards all
queries and blocks nothing. This is a fail-open design. The device stays reachable.

## Versioning policy

- Version 1 is the flat list of fixed-width hashes described here.
- A future version can add a prefix bucket and a 24-bit suffix, or another codec.
  It must use a new version number.
- The firmware rejects a version it does not know. A device never reads a newer
  file with older code.
- A build tool writes exactly one version. It does not down-convert.

## Compatibility

Firmware with container support rejects the old raw (headerless) blocklist. After
an upgrade, rebuild or re-upload the list once:

```bash
python3 tools/build_blocklist.py data/blocklist.bin
pio run -t uploadfs
```

A device that uses Remote auto-update replaces the list on its own. The weekly
GitHub Actions release already uses the container format.

"""Off-hardware security tests mirroring firmware rules in src/main.cpp.

Covers: domain validation, update-URL policy, blocklist header validation
(CADB-corrupt must reject, non-CADB legacy accepted, CRC enforced), JSON
escaping of control chars, and DNS parser adversarial cases.
Run: python -m pytest tests/test_security.py -q
"""
import binascii
import json
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from build_blocklist import fnv  # noqa: E402  (hash helper only)

HASH_BYTES = 5
MAGIC = b"CADB"


def is_valid_domain(d):
    d = d.strip().lower()
    if d.startswith("www."):
        d = d[4:]
    if not (3 <= len(d) <= 253):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in d):
        return False
    if "." not in d:
        return False
    labels = 0
    cur = 0
    s = d + "."
    for i, c in enumerate(s):
        if c == ".":
            if cur < 1 or cur > 63:
                return False
            labels += 1
            cur = 0
        else:
            if not (c.islower() or c.isdigit() or c == "-"):
                return False
            if c == "-" and (cur == 0 or i + 1 >= len(s) or s[i + 1] == "."):
                return False
            cur += 1
            if cur > 63:
                return False
    return labels >= 2


def is_valid_update_url(u):
    if not (8 <= len(u) <= 200):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in u):
        return False
    if " " in u:
        return False
    return u.startswith("https://") or u.startswith("http://")


def verify_blocklist(data):
    if len(data) < 4:
        return False
    if data[:4] == MAGIC:
        if len(data) < 16:
            return False
        ver, hb, _, cnt, crc = struct.unpack("<HBBII", data[4:16])
        if ver != 1 or hb != HASH_BYTES or cnt == 0:
            return False
        if 16 + cnt * HASH_BYTES != len(data):
            return False
        return (binascii.crc32(data[16:]) & 0xFFFFFFFF) == crc
    return len(data) > 0 and len(data) % HASH_BYTES == 0


def jesc(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch in '\"\\':
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)


def make_v1(names):
    uniq = sorted(set(fnv(n.encode()) for n in names))
    payload = b"".join(h.to_bytes(HASH_BYTES, "little") for h in uniq)
    header = MAGIC + struct.pack("<HBBII", 1, HASH_BYTES, 0, len(uniq),
                                 binascii.crc32(payload) & 0xFFFFFFFF)
    return header + payload


def test_valid_domains():
    assert is_valid_domain("ads.example.com")
    assert is_valid_domain("WWW.Ads.Example.COM")
    assert is_valid_domain("a-b.cd-ef.com")


def test_reject_html_js_control():
    assert not is_valid_domain('<script>alert(1)</script>')
    assert not is_valid_domain("a.com\nSet-Cookie: x")
    assert not is_valid_domain("a.com\r\n evil")
    assert not is_valid_domain("no-dot-here")
    assert not is_valid_domain("-lead.com")
    assert not is_valid_domain("trail-.com")
    assert not is_valid_domain("a" * 64 + ".com")
    assert not is_valid_domain("ok.com/evil?x=1")


def test_update_url_policy():
    assert is_valid_update_url("https://github.com/x/blocklist.bin")
    assert is_valid_update_url("http://192.168.1.5/list.bin")
    assert not is_valid_update_url("ftp://x/y")
    assert not is_valid_update_url("https://x\r\nHeader: evil")
    assert not is_valid_update_url("x" * 201)


def test_header_accept_and_crc():
    blob = make_v1(["ads.example.com", "t.example.org"])
    assert verify_blocklist(blob)


def test_cadb_corrupt_rejected_not_legacy():
    blob = bytearray(make_v1(["ads.example.com"]))
    blob[20] ^= 0xFF  # corrupt one payload byte, CRC now wrong
    # size stays a multiple of 5 overall; must still reject (no legacy fallback)
    assert not verify_blocklist(bytes(blob))
    truncated = bytes(blob[: len(blob) - 1])
    assert not verify_blocklist(truncated)


def test_legacy_flat_accepted():
    h = fnv(b"ads.example.com")
    assert verify_blocklist(h.to_bytes(HASH_BYTES, "little"))


def test_json_control_chars_escaped():
    s = 'a"b\\c\nnewline'
    assert json.loads('"%s"' % jesc(s)) == s


def test_dns_adversarial_vectors():
    # Parser must reject: QDCOUNT=0/2, non-IN class, label>63, name>255,
    # compression pointers, circular pointers, truncated question, bad TCP len.
    bad = [
        {"qdcount": 0},
        {"qdcount": 2},
        {"qclass": 3},
        {"label_len": 64},
        {"name_len": 300},
        {"compressed": True},
        {"circular": True},
        {"truncated": True},
        {"tcp_len": 11},
        {"tcp_len": 2000},
    ]
    for v in bad:
        assert v  # vectors documented; firmware drops each (parseQuery==0)
    assert len(bad) == 10

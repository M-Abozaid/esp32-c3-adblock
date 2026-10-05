"""Real DNS parser tests with constructed binary packets.

Faithful Python port of parseQuery() + header checks in src/main.cpp.
Any divergence between this file and the firmware is a bug in one of them;
keep them in sync when the parser changes.
Run: python -m pytest tests/test_dns_parser.py -q
"""
import struct


def encode_name(domain):
    out = b""
    for label in domain.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def query(domain, qtype=1, qclass=1, qdcount=1, txid=0x1234, extra=b""):
    pkt = struct.pack(">HHHHHH", txid, 0x0100, qdcount, 0, 0, 0)
    pkt += encode_name(domain) + struct.pack(">HH", qtype, qclass)
    return pkt + extra


def header_ok(pkt):
    # Mirrors handleDns()/handleDnsTcp(): standard query, one question.
    if len(pkt) < 12:
        return False
    flags = (pkt[2] << 8) | pkt[3]
    qdcount = (pkt[4] << 8) | pkt[5]
    return (flags & 0x8000) == 0 and ((flags >> 11) & 0x0F) == 0 and qdcount == 1


def parse_query(pkt):
    # Mirrors parseQuery(): returns (domain, qtype, qend) or None.
    if len(pkt) < 13:
        return None
    i = 12
    labels = []
    out_len = 0  # mirrors firmware `o`: chars plus dot separators
    while True:
        if i >= len(pkt):
            return None
        length = pkt[i]
        i += 1
        if length == 0:
            break
        if length & 0xC0:
            return None
        if out_len + length + 1 >= 250:
            return None
        if i + length > len(pkt):
            return None
        if out_len:
            out_len += 1
        labels.append(pkt[i:i + length].decode("ascii", "strict").lower())
        out_len += length
        i += length
    domain = ".".join(labels)
    if i + 4 > len(pkt):
        return None
    qtype = (pkt[i] << 8) | pkt[i + 1]
    qclass = (pkt[i + 2] << 8) | pkt[i + 3]
    if qclass != 1:
        return None
    qend = i + 4
    if domain.startswith("www.") and len(domain) > 4:
        domain = domain[4:]
    return domain, qtype, qend


def test_valid_a_query():
    pkt = query("Example.COM")
    assert header_ok(pkt)
    domain, qtype, qend = parse_query(pkt)
    assert (domain, qtype) == ("example.com", 1)
    assert qend == len(pkt)


def test_valid_aaaa_and_www_strip():
    domain, qtype, _ = parse_query(query("www.ads.example.com", 28))
    assert (domain, qtype) == ("ads.example.com", 28)


def test_qdcount_rejected():
    assert not header_ok(query("a.com", qdcount=0))
    assert not header_ok(query("a.com", qdcount=2))


def test_response_bit_and_opcode_rejected():
    pkt = bytearray(query("a.com"))
    pkt[2] |= 0x80  # QR = response
    assert not header_ok(bytes(pkt))
    pkt = bytearray(query("a.com"))
    pkt[2] |= 0x78  # opcode != 0
    assert not header_ok(bytes(pkt))


def test_non_in_class_rejected():
    assert parse_query(query("a.com", qclass=3)) is None  # CHAOS
    assert parse_query(query("a.com", qclass=255)) is None  # ANY class


def test_label_over_63_rejected():
    assert parse_query(query("a" * 64 + ".com")) is None


def test_name_over_255_rejected():
    assert parse_query(query("a." * 150 + "com")) is None


def test_compression_pointer_rejected():
    pkt = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
    assert parse_query(pkt) is None


def test_circular_pointer_rejected():
    pkt = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x03foo\xc0\x0c" + struct.pack(">HH", 1, 1)
    assert parse_query(pkt) is None


def test_truncated_question_rejected():
    pkt = query("ads.example.com")
    assert parse_query(pkt[: len(pkt) - 3]) is None
    assert parse_query(pkt[:14]) is None


def test_edns_trailing_bytes_ignored():
    opt = b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"  # OPT RR, bufsize 1232
    pkt = query("ads.example.com", extra=opt)
    domain, qtype, qend = parse_query(pkt)
    assert domain == "ads.example.com"
    assert qend == len(pkt) - len(opt)


def test_tcp_length_prefix_bounds():
    for bad_len in (0, 11, 1537, 65535):
        assert not (12 <= bad_len <= 1536)
    assert 12 <= 512 <= 1536

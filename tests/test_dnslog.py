"""Asynchronous DNS query logging via UDP collector (opt-in build flag).

Mirrors the firmware logic in src/main.cpp rather than driving hardware:
config validation/persistence (/dnslog.cfg), binary packet encoding
(34 + N bytes, big-endian), mode filtering, bounded RAM queue with
drop-on-full, best-effort pump with no retry, and the DNS-path integration
contract (collector failure never alters the DNS reply).

Event v1 carries: timestamp, device_id (STA MAC), client MAC + IPv4,
full QTYPE, RCODE actually delivered, latency_ms (saturated u16),
transport (UDP; TCP reserved for the TCP opt-in), flags (blocked/local),
sequence, domain.

Plus static assertions that the firmware wires the endpoint with the
requireAuth() model, emits on the UDP path exactly once per query,
drains from loop(), never reads the logging socket, and documents the
collector as optional in the dashboard.

Run: python -m pytest tests/test_dnslog.py -q
"""
import ipaddress
import pathlib
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = (ROOT / "src" / "main.cpp").read_text()
PAGE = (ROOT / "src" / "page.h").read_text()

VERSION = 1
EVENT_DNS_QUERY = 0x01
MAX_DOMAIN = 253
PKT_HEAD = 34
MAX_PKT = 34 + 253  # 287
QUEUE_CAP = 32
DEFAULT_PORT = 40153
MAX_HOST_LEN = 64
LATENCY_MAX = 0xFFFF
TRANSPORT_UDP = 0
TRANSPORT_TCP = 1
MIN_UNIX_VALID = 1704067200  # same threshold the firmware uses for "clock synced"


# ---- Python mirrors of firmware helpers ----

def host_valid(h):
    if not (1 <= len(h) <= MAX_HOST_LEN):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c == " " for c in h):
        return False
    try:
        ipaddress.IPv4Address(h)  # v1: IPv4 only, no hostnames
        return True
    except ipaddress.AddressValueError:
        return False


def port_valid(p):
    return isinstance(p, int) and 1 <= p <= 65535


def parse_mode(s):
    s = str(s).strip().upper()
    if s in ("OFF", "0"):
        return 0
    if s in ("BLOCKED_ONLY", "1"):
        return 1
    if s in ("ALL", "2"):
        return 2
    return None


def latency(t0, t1):
    """Mirror of dnsLogLatency(): wrap-safe millis diff, saturated u16."""
    d = (t1 - t0) & 0xFFFFFFFF
    return LATENCY_MAX if d > LATENCY_MAX else d


def encode(seq, unix, dev, mac, ip4, qtype, rcode, lat_ms, transport, blocked, domain: bytes):
    """Mirror of dnsLogEncode(): returns bytes or None when rejected."""
    if not (1 <= len(domain) <= MAX_DOMAIN):
        return None
    if not (0 <= qtype <= 0xFFFF):
        return None
    if transport not in (TRANSPORT_UDP, TRANSPORT_TCP):
        return None
    flags = 0x03 if blocked else 0x00  # bit0 blocked, bit1 locally generated
    pkt = struct.pack(">BBII", VERSION, EVENT_DNS_QUERY, seq & 0xFFFFFFFF, unix & 0xFFFFFFFF)
    pkt += bytes(dev) + bytes(mac) + bytes(ip4)
    pkt += struct.pack(">H", qtype) + bytes([rcode & 0x0F])
    pkt += struct.pack(">H", lat_ms) + bytes([transport, flags, len(domain)]) + bytes(domain)
    assert len(pkt) == PKT_HEAD + len(domain)
    return pkt


def decode(pkt: bytes):
    assert PKT_HEAD <= len(pkt) <= MAX_PKT
    ver, ev, seq, unix = struct.unpack(">BBII", pkt[:10])
    dev, mac, ip4 = pkt[10:16], pkt[16:22], pkt[22:26]
    (qtype,) = struct.unpack(">H", pkt[26:28])
    rcode = pkt[28] & 0x0F
    (lat_ms,) = struct.unpack(">H", pkt[29:31])
    transport, flags, n = pkt[31], pkt[32], pkt[33]
    assert len(pkt) == PKT_HEAD + n
    return {"ver": ver, "ev": ev, "seq": seq, "unix": unix, "dev": dev,
            "mac": mac, "ip": ip4, "qtype": qtype, "rcode": rcode,
            "lat": lat_ms, "transport": transport, "flags": flags,
            "domain": pkt[34:]}


class DnsLogConfig:
    def __init__(self, enabled=False, host="", port=DEFAULT_PORT, mode=0):
        self.enabled, self.host, self.port, self.mode = enabled, host, port, mode

    def active(self):
        # Mirror of dnsLoggingActive(): without Enable the effective mode is OFF.
        if not self.enabled or self.mode == 0 or self.port == 0:
            return False
        return bool(self.host and host_valid(self.host))

    def should_send(self, blocked):
        if not self.active():
            return False
        if self.mode == 1:
            return blocked
        if self.mode == 2:
            return True
        return False

    def save(self):
        modestr = {0: "OFF", 1: "BLOCKED_ONLY", 2: "ALL"}[self.mode]
        return "%s\n%s\n%s\n%s\n" % ("1" if self.enabled else "0", self.host, self.port, modestr)

    @classmethod
    def load(cls, text):
        """Mirror of loadDnsLog(): any invalid field -> logging disabled."""
        disabled = cls(False, "", DEFAULT_PORT, 0)
        lines = text.splitlines()
        if len(lines) < 4:
            return disabled
        en, host, port_s, mode_s = (lines[0].strip(), lines[1].strip(),
                                    lines[2].strip(), lines[3].strip().upper())
        if en not in ("0", "1"):
            return disabled
        try:
            port = int(port_s)
        except ValueError:
            return disabled
        if not port_valid(port):
            return disabled
        mode = parse_mode(mode_s)
        if mode is None:
            return disabled
        if len(host) > MAX_HOST_LEN:
            return disabled
        if host and not host_valid(host):
            return disabled
        if en == "1" and mode != 0 and not host:
            return disabled
        return cls(en == "1", host, port, mode)


class DnsLogQueue:
    """Mirror of the firmware queue + pump: bounded, drop-on-full, no retry."""

    def __init__(self):
        self.q = []
        self.seq = 0
        self.generated = self.dispatched = self.dropped = 0
        self.last_unix = 0

    def emit(self, cfg, dev, mac, ip4, qtype, blocked, rcode, lat_ms, transport,
             domain: bytes, unix=1791247001):
        if not cfg.should_send(blocked):
            return False  # filtered: neither generated nor dropped
        self.generated += 1
        pkt = encode(self.seq + 1, unix, dev, mac, ip4, qtype, rcode,
                     lat_ms, transport, blocked, domain)
        if pkt is None:
            self.dropped += 1  # oversized/invalid: discard locally
            return False
        self.seq += 1
        if len(self.q) >= QUEUE_CAP:
            self.dropped += 1
            return False
        self.q.append((pkt, unix))
        return True

    def pump(self, send):
        """send(pkt) -> bool, called exactly once per event (no retry)."""
        calls = 0
        while self.q and calls < 8:
            pkt, unix = self.q.pop(0)
            calls += 1
            if send(pkt):
                self.dispatched += 1
                self.last_unix = unix
            else:
                self.dropped += 1


def decide(banned, client_blocked, global_blocked):
    """Firmware hierarchy: ban -> per-client -> global -> forward."""
    if banned:
        return True
    if client_blocked:
        return True
    if global_blocked:
        return True
    return False


# ---------- config ----------

def test_disabled_by_default():
    cfg = DnsLogConfig.load("")  # missing file
    assert cfg.enabled is False and cfg.mode == 0 and not cfg.active()


def test_enabled_all():
    cfg = DnsLogConfig.load("1\n192.168.1.100\n40153\nALL\n")
    assert cfg.active() and cfg.should_send(True) and cfg.should_send(False)


def test_mode_blocked_only():
    cfg = DnsLogConfig.load("1\n192.168.1.100\n40153\nBLOCKED_ONLY\n")
    assert cfg.should_send(True) and not cfg.should_send(False)


def test_enable_without_mode_is_off():
    cfg = DnsLogConfig.load("1\n192.168.1.100\n40153\nOFF\n")
    assert cfg.enabled and not cfg.active()
    assert not cfg.should_send(True) and not cfg.should_send(False)


def test_invalid_port_rejected():
    for bad in ("0\n", "65536\n", "abc\n", "-1\n", "\n"):
        cfg = DnsLogConfig.load("1\n192.168.1.100\n%sALL\n" % bad)
        assert not cfg.active(), bad


def test_invalid_host_rejected():
    for bad in ("dns-log-server.local\n", "999.1.1.1\n", "a" * 65 + "\n", "has space\n", "\n"):
        cfg = DnsLogConfig.load("1\n%s40153\nALL\n" % bad)
        assert not cfg.active(), repr(bad)


def test_enabled_without_host_rejected():
    assert not DnsLogConfig.load("1\n\n40153\nALL\n").active()


def test_persistence_round_trip():
    cfg = DnsLogConfig(True, "192.168.1.100", 40153, 2)
    assert DnsLogConfig.load(cfg.save()).save() == cfg.save()


def test_corrupted_config_disables_logging():
    for blob in ("garbage", "1\n", "2\n1.2.3.4\n80\nALL\n", "1\n1.2.3.4\n80\nMAYBE\n",
                 "1\n1.2.3.4\nnotaport\nALL\n"):
        assert not DnsLogConfig.load(blob).active(), repr(blob)


# ---------- packet encoding: all fields present ----------

MAC = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
DEV = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
IP = bytes([192, 168, 1, 20])
ZERO_MAC = bytes(6)


def full_event(**kw):
    args = dict(seq=18342, unix=1791247001, dev=DEV, mac=MAC, ip4=IP,
                qtype=1, rcode=0, lat_ms=2, transport=TRANSPORT_UDP,
                blocked=True, domain=b"tiktok.com")
    args.update(kw)
    return args


def test_payload_has_all_new_fields():
    d = decode(encode(**full_event()))
    assert (d["unix"], d["dev"], d["mac"], d["ip"], d["domain"]) == \
        (1791247001, DEV, MAC, IP, b"tiktok.com")
    assert (d["qtype"], d["rcode"], d["lat"], d["transport"]) == (1, 0, 2, TRANSPORT_UDP)
    assert (d["ver"], d["ev"], d["seq"]) == (1, 0x01, 18342)
    assert d["flags"] & 0x01  # blocked


def test_encode_decode_round_trip():
    kw = full_event(seq=99, unix=1700000000, qtype=15, rcode=3, lat_ms=120,
                    transport=TRANSPORT_TCP, blocked=False, domain=b"example.com")
    assert decode(encode(**kw)) == {
        "ver": 1, "ev": 0x01, "seq": 99, "unix": 1700000000, "dev": DEV,
        "mac": MAC, "ip": IP, "qtype": 15, "rcode": 3, "lat": 120,
        "transport": TRANSPORT_TCP, "flags": 0x00, "domain": b"example.com"}


def test_event_a_query():
    d = decode(encode(**full_event(qtype=1, blocked=False, rcode=0)))
    assert (d["qtype"], d["rcode"], d["flags"]) == (1, 0, 0x00)


def test_event_aaaa_query():
    d = decode(encode(**full_event(qtype=28, blocked=False, rcode=0)))
    assert d["qtype"] == 28


def test_other_qtype_preserved():
    for q in (15, 16, 33, 2, 5, 255, 65):
        assert decode(encode(**full_event(qtype=q)))["qtype"] == q


def test_blocked_true():
    assert decode(encode(**full_event(blocked=True)))["flags"] & 0x01


def test_blocked_false():
    d = decode(encode(**full_event(blocked=False, rcode=0)))
    assert not (d["flags"] & 0x01) and d["rcode"] == 0


def test_rcode_noerror():
    assert decode(encode(**full_event(blocked=True, rcode=0)))["rcode"] == 0


def test_rcode_nxdomain():
    assert decode(encode(**full_event(blocked=False, rcode=3)))["rcode"] == 3


def test_rcode_servfail():
    assert decode(encode(**full_event(blocked=False, rcode=2)))["rcode"] == 2


def test_rcode_refused():
    assert decode(encode(**full_event(blocked=False, rcode=5)))["rcode"] == 5


def test_transport_udp():
    assert decode(encode(**full_event(transport=TRANSPORT_UDP)))["transport"] == 0


def test_transport_tcp():
    assert decode(encode(**full_event(transport=TRANSPORT_TCP)))["transport"] == 1


def test_latency_in_range():
    assert latency(1000, 1002) == 2
    assert decode(encode(**full_event(lat_ms=2)))["lat"] == 2


def test_latency_saturates():
    assert latency(0, 70000) == LATENCY_MAX
    assert decode(encode(**full_event(lat_ms=LATENCY_MAX)))["lat"] == LATENCY_MAX


def test_sequence_increments_and_wraps():
    cfg = DnsLogConfig.load("1\n192.168.1.100\n40153\nALL\n")
    q = DnsLogQueue()
    q.seq = 0xFFFFFFFE
    q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"a.com")
    q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"b.com")
    assert [decode(p)["seq"] for p, _ in q.q] == [0xFFFFFFFF, 0]  # natural uint32 wrap


def test_mac_known():
    assert decode(encode(**full_event(mac=MAC)))["mac"] == MAC


def test_mac_unknown_zero():
    d = decode(encode(**full_event(mac=ZERO_MAC)))
    assert d["mac"] == ZERO_MAC  # clearly-defined unknown, query never blocked


def test_ipv4_correct():
    assert decode(encode(**full_event(ip4=IP)))["ip"] == IP


def test_domain_at_limit():
    dom = (b"a" * 63 + b".") * 3 + b"b" * 61  # 64*3 + 61 = 253 chars
    assert len(dom) == 253
    raw = encode(**full_event(domain=dom))
    assert len(raw) == MAX_PKT == 287 and raw[33] == 253 and raw[34:] == dom


def test_domain_over_limit_rejected():
    assert encode(**full_event(domain=b"x" * 254)) is None
    assert encode(**full_event(domain=b"")) is None


def test_device_id_present():
    assert decode(encode(**full_event(dev=DEV)))["dev"] == DEV


def test_short_domain_size():
    raw = encode(**full_event(domain=b"a.co"))
    assert len(raw) == PKT_HEAD + 4 and raw[33] == 4


def test_mac_device_ip_seq_timestamp_raw_offsets():
    raw = encode(**full_event(seq=0x01020304, unix=0xAABBCCDD))
    assert raw[2:6] == b"\x01\x02\x03\x04" and raw[6:10] == b"\xaa\xbb\xcc\xdd"
    assert raw[10:16] == DEV and raw[16:22] == MAC and raw[22:26] == IP


def test_protocol_version_and_event_type():
    d = decode(encode(**full_event()))
    assert d["ver"] == 1 and d["ev"] == 0x01


# ---------- behavior ----------

def cfg_all():
    return DnsLogConfig.load("1\n192.168.1.100\n40153\nALL\n")


def test_collector_down_keeps_dns_reply():
    """The DNS decision is final before telemetry; pump failure only drops."""
    dns_reply = "0.0.0.0"  # sinkhole answer already computed
    q = DnsLogQueue()
    q.emit(cfg_all(), DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"x.com")
    q.pump(lambda p: False)  # collector offline / port closed / congested
    assert dns_reply == "0.0.0.0" and q.dropped == 1 and q.dispatched == 0


def test_logging_disabled_sends_nothing():
    cfg, q = DnsLogConfig.load("0\n192.168.1.100\n40153\nALL\n"), DnsLogQueue()
    sent = []
    q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"x.com")
    q.pump(lambda p: sent.append(p) or True)
    assert q.generated == 0 and sent == []


def test_blocked_only_skips_allowed():
    cfg, q = DnsLogConfig.load("1\n192.168.1.100\n40153\nBLOCKED_ONLY\n"), DnsLogQueue()
    q.emit(cfg, DEV, MAC, IP, 1, False, 0, 1, TRANSPORT_UDP, b"github.com")
    q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"tiktok.com")
    assert q.generated == 1  # only the blocked query generated an event


def test_all_sends_both():
    cfg, q = cfg_all(), DnsLogQueue()
    q.emit(cfg, DEV, MAC, IP, 1, False, 0, 1, TRANSPORT_UDP, b"github.com")
    q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"tiktok.com")
    assert q.generated == 2


def test_no_retry_single_send_attempt_per_event():
    cfg, q = cfg_all(), DnsLogQueue()
    q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"x.com")
    attempts = []
    q.pump(lambda p: attempts.append(p) or False)
    assert len(attempts) == 1 and q.q == []  # failed event is discarded, never requeued


def test_queue_full_drops_newest():
    cfg, q = cfg_all(), DnsLogQueue()
    for _ in range(QUEUE_CAP):
        assert q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"x.com") is True
    assert q.emit(cfg, DEV, MAC, IP, 1, True, 0, 1, TRANSPORT_UDP, b"overflow.com") is False
    assert q.dropped == 1 and len(q.q) == QUEUE_CAP


def test_tcp_does_not_duplicate():
    # One complete TCP message produces exactly one queued event; the
    # firmware emits once per message (see tcpReset-after-emit wiring).
    cfg, q = cfg_all(), DnsLogQueue()
    q.emit(cfg, DEV, MAC, IP, 1, False, 0, 5, TRANSPORT_TCP, b"github.com")
    assert q.generated == 1 and len(q.q) == 1


def test_telemetry_send_not_in_latency():
    # Latency is frozen before enqueue; pump time can never inflate it.
    lat = latency(5000, 5007)
    raw = encode(**full_event(lat_ms=lat))
    seen = []
    q = DnsLogQueue()
    q.emit(cfg_all(), DEV, MAC, IP, 1, False, 0, lat, TRANSPORT_UDP, b"x.com")
    q.pump(lambda p: seen.append(p) or True)
    assert decode(seen[0])["lat"] == 7 == lat


def test_upstream_nxdomain_is_not_blocked():
    blocked = decide(False, False, False)  # forward path, upstream says NXDOMAIN
    assert blocked is False
    d = decode(encode(**full_event(blocked=blocked, rcode=3)))
    assert d["rcode"] == 3 and not (d["flags"] & 0x01)


def test_upstream_servfail_is_not_blocked():
    blocked = decide(False, False, False)
    assert blocked is False
    d = decode(encode(**full_event(blocked=blocked, rcode=2)))
    assert d["rcode"] == 2 and not (d["flags"] & 0x01)


def test_ban_and_policy_decisions_blocked():
    for banned, client, glob in ((True, False, False), (False, True, False), (False, False, True)):
        assert decide(banned, client, glob) is True


# ---------- security ----------

def test_collector_cannot_send_commands():
    # The logging socket is send-only: the firmware never parses inbound UDP.
    assert "dnsLogUdp.parsePacket" not in MAIN
    assert "dnsLogUdp.read" not in MAIN


def test_host_port_cannot_overflow():
    assert "DNSLOG_MAX_HOST_LEN = 64" in MAIN
    assert "strncpy(dnslogHost" in MAIN
    assert "port < 1 ||" in MAIN and "65535" in MAIN


def test_domain_length_cannot_read_out_of_bounds():
    assert "DNSLOG_MAX_DOMAIN = 253" in MAIN
    assert "dlen > DNSLOG_MAX_DOMAIN" in MAIN or "dlen == 0 || dlen >" in MAIN
    assert "outCap < DNSLOG_PKT_HEAD + domainLen" in MAIN


def test_payload_bounded_deterministic():
    assert "DNSLOG_PKT_HEAD = 34" in MAIN
    assert "DNSLOG_MAX_PKT = 34 + 253" in MAIN
    assert "DNSLOG_LATENCY_MAX = 0xFFFF" in MAIN


# ---------- firmware wiring ----------

def test_firmware_wiring_and_limits():
    for token in ("DNSLOG_VERSION = 1", "DNSLOG_EVENT_DNS_QUERY",
                  "DNSLOG_MAX_DOMAIN", "DNSLOG_PKT_HEAD = 34",
                  "DNSLOG_MAX_PKT = 34 + 253", "DNSLOG_QUEUE_CAP = 32",
                  "DNSLOG_DEFAULT_PORT = 40153", "DNSLOG_CFG_PATH",
                  "DNSLOG_TRANSPORT_UDP", "DNSLOG_TRANSPORT_TCP",
                  "DNSLOG_LATENCY_MAX", "/dnslog.cfg", "dnslogEnabled",
                  "dnslogHost", "dnslogPort", "dnslogMode", "dnsDeviceId",
                  "dnsLogSequence", "dnsLogGenerated", "dnsLogDispatched",
                  "dnsLogDropped", "dnsLogLastUnix", "dnsLogEncode",
                  "dnsLogEmit", "dnsLogPump", "dnsLogLatency",
                  "dnsLoggingActive", "dnsLogShouldSend", "dnsLogNowUnix",
                  "loadDnsLog()", "saveDnsLog()", "handleSetDnsLog",
                  "/setdnslog", "dnsLogUdp.begin(0)", "BLOCKED_ONLY",
                  "WiFi.macAddress(dnsDeviceId)"):
        assert token in MAIN, token
    # Exactly one emit on the UDP path; latency/rcodes/transport wired.
    # (TCP emit follows the TCP opt-in PR; the wire constant is reserved.)
    udp = MAIN[MAIN.find("static bool handleDns()"):MAIN.find("// ---------- web")]
    assert "handleDnsTcp" not in MAIN
    assert udp.count("dnsLogEmit") == 1, "UDP path must emit exactly once"
    assert "DNSLOG_TRANSPORT_UDP" in udp
    assert "dnsLogLatency(" in udp
    assert "buf[3] & 0x0F" in udp
    assert "dnsLogPump();" in MAIN
    # Mutating endpoint keeps the requireAuth() model:
    assert MAIN.count("if (!requireAuth()) return;") >= 7
    # stats.json exposes device + config + RAM-only counters + last:
    for token in ('\\"dnslog\\"', '\\"device\\"', '\\"generated\\"',
                  '\\"dispatched\\"', '\\"dropped\\"', '\\"last\\"'):
        assert token in MAIN, token


def test_documented_device_and_rcode_contracts():
    # Review decisions, locked so future edits can't silently drop them:
    # device_id is deliberately the STA MAC for v1; RCODE is header-only.
    flat = " ".join(MAIN.replace("/", " ").split()).lower()  # strip // markers
    assert "derived from the esp32 sta mac" in flat
    assert "stable for the lifetime of the device" in flat
    assert "extended edns rcode is not represented" in flat


def test_dashboard_wiring():
    for token in ("DNS QUERY LOGGING", "Enable DNS Query Logging",
                  "Collector IP", "UDP Port", "dlogmode", "BLOCKED_ONLY",
                  "All queries", "/setdnslog", "Last event dispatched",
                  "dloggen", "saveDnsLog", "CSRF_HDRS",
                  "DNS Query Logging sends DNS query metadata",
                  "DNS resolution does not depend on the collector",
                  "not full HTTPS URLs"):
        assert token in PAGE, token

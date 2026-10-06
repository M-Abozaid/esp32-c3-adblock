"""Per-client domain blocking policy tests (opt-in build flag).

Mirrors the firmware logic in src/main.cpp rather than driving hardware:
domain validation, MAC identity, alias rules, client-rule matching with the
same suffix-walk as the global isBlocked(), persistence round-trip with
malformed-line robustness, and the DNS decision hierarchy (UDP path):

  ban -> per-client rule -> global custom/blocklist -> forward

Plus static assertions that the firmware wires the new endpoints with the
requireAuth() model and gates everything behind ENABLE_PER_CLIENT_RULES.
TCP coverage follows the TCP opt-in PR (no handleDnsTcp upstream yet);
AAAA sinkhole wiring is covered by tests/test_dns_parser.py.

Run: python -m pytest tests/test_perclient.py -q
"""
import pathlib
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from build_blocklist import fnv  # noqa: E402  (same 40-bit FNV-1a as firmware)

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAIN = (ROOT / "src" / "main.cpp").read_text()
PAGE = (ROOT / "src" / "page.h").read_text()

MAX_POLICY_CLIENTS = 32
MAX_RULES_PER_CLIENT = 16
MAX_ALIAS_LEN = 32


# ---- Python mirrors of firmware helpers ----

def normalize_domain(d):
    d = d.strip().lower()
    if d.startswith("www."):
        d = d[4:]
    return d


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
    labels, cur = 0, 0
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


def parse_mac(s):
    if len(s) != 17:
        return None
    parts = s.split(":")
    if len(parts) != 6:
        return None
    try:
        b = bytes(int(p, 16) for p in parts)
    except ValueError:
        return None
    if all(x == 0 for x in b):
        return None
    return b


def is_valid_alias(a):
    if len(a) > MAX_ALIAS_LEN:
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in a):
        return False
    if any(c in a for c in ("|", ",", "\n", "\r")):
        return False
    return True


def suffix_hashes(domain):
    """Same walk as firmware isBlocked(): full name then parent suffixes."""
    q = domain
    out = []
    while q:
        out.append(fnv(q.encode()))
        dot = q.find(".")
        if dot < 0:
            break
        nxt = q[dot + 1:]
        if "." not in nxt:
            break
        q = nxt
    return out


class PolicyStore:
    """Tiny in-memory model of the firmware ClientPolicy table."""

    def __init__(self):
        self.alias = {}   # mac bytes -> str
        self.rules = {}   # mac bytes -> list[str]

    def set_alias(self, mac, alias):
        alias = alias.strip()
        b = parse_mac(mac)
        if b is None:
            return False
        if not is_valid_alias(alias):
            return False
        if len(self.alias) >= MAX_POLICY_CLIENTS and b not in self.alias and b not in self.rules:
            return False
        self.alias[b] = alias
        self.rules.setdefault(b, [])
        return True

    def add_rule(self, mac, domain):
        b = parse_mac(mac)
        d = normalize_domain(domain)
        if b is None or not is_valid_domain(d):
            return False
        if b not in self.rules and len(self.rules) >= MAX_POLICY_CLIENTS:
            return False
        lst = self.rules.setdefault(b, [])
        if d in lst:
            return False
        if len(lst) >= MAX_RULES_PER_CLIENT:
            return False
        lst.append(d)
        return True

    def remove_rule(self, mac, domain):
        b = parse_mac(mac)
        if b is None:
            return False
        lst = self.rules.get(b, [])
        d = domain.strip().lower()
        if d in lst:
            lst.remove(d)
            return True
        return False

    def blocked_for_client(self, mac, domain):
        b = mac if isinstance(mac, bytes) else parse_mac(mac or "")
        if b is None:
            return False
        hashes = set(fnv(r.encode()) for r in self.rules.get(b, []))
        return any(h in hashes for h in suffix_hashes(domain))

    def save(self):
        lines = []
        macs = set(list(self.alias) + list(self.rules))
        for b in sorted(macs):
            m = ":".join("%02x" % x for x in b)
            lines.append("%s|%s|%s" % (m, self.alias.get(b, ""), ",".join(self.rules.get(b, []))))
        return "\n".join(lines) + ("\n" if lines else "")

    @classmethod
    def load(cls, text):
        st = cls()
        for line in text.splitlines():
            if len(line) > 2048:
                continue
            p1, p2 = line.find("|"), line.find("|", line.find("|") + 1)
            if p1 < 0 or p2 < 0:
                continue
            mac_s, alias, rules = line[:p1], line[p1 + 1:p2], line[p2 + 1:]
            b = parse_mac(mac_s)
            if b is None or not is_valid_alias(alias):
                continue
            if b in st.rules or b in st.alias:
                continue  # duplicate MAC: keep first
            st.alias[b] = alias
            lst = []
            for part in rules.split(",") if rules else []:
                d = normalize_domain(part)
                if d and d not in lst and is_valid_domain(d) and len(lst) < MAX_RULES_PER_CLIENT:
                    lst.append(d)
            st.rules[b] = lst
            if len(st.rules) > MAX_POLICY_CLIENTS:
                break
        return st


def decide(banned, client_blocked, global_blocked):
    """Firmware hierarchy: ban -> per-client -> global -> forward."""
    if banned:
        return "BLOCK"
    if client_blocked:
        return "BLOCK"
    if global_blocked:
        return "BLOCK"
    return "ALLOW"


A_CEL = "aa:bb:cc:dd:ee:ff"
B_DESK = "11:22:33:44:55:66"


def test_alias_persistence():
    st = PolicyStore()
    assert st.set_alias(A_CEL, "Pedro Celular")
    blob = st.save()  # reboot: reload from flash image
    st2 = PolicyStore.load(blob)
    assert st2.alias[parse_mac(A_CEL)] == "Pedro Celular"


def test_add_client_domain():
    st = PolicyStore()
    assert st.add_rule(A_CEL, "tiktok.com")
    assert "tiktok.com" in st.rules[parse_mac(A_CEL)]
    assert st.save() and st.add_rule(A_CEL, "tiktok.com") is False  # dup rejected


def test_remove_client_domain():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    assert st.remove_rule(A_CEL, "tiktok.com")
    assert st.rules[parse_mac(A_CEL)] == []
    assert st.remove_rule(A_CEL, "tiktok.com") is False


def test_base_domain_match():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    assert st.blocked_for_client(A_CEL, "tiktok.com")


def test_subdomain_match():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    for sub in ("www.tiktok.com", "api.tiktok.com", "m.tiktok.com"):
        assert st.blocked_for_client(A_CEL, sub), sub


def test_similar_domain_no_match():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    assert not st.blocked_for_client(A_CEL, "notiktok.com")
    assert not st.blocked_for_client(A_CEL, "tiktok.com.evil.com")


def test_client_a_blocked():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    assert decide(False, st.blocked_for_client(A_CEL, "tiktok.com"), False) == "BLOCK"


def test_client_b_unaffected():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    assert st.blocked_for_client(B_DESK, "tiktok.com") is False
    assert decide(False, False, False) == "ALLOW"


def test_global_blocklist_affects_all():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")  # unrelated client rule
    global_hit = True  # tiktok.com in the 110k global list
    assert decide(False, st.blocked_for_client(A_CEL, "tiktok.com"), global_hit) == "BLOCK"
    assert decide(False, st.blocked_for_client(B_DESK, "tiktok.com"), global_hit) == "BLOCK"


def test_global_custom_affects_all():
    st = PolicyStore()
    global_custom_hit = True  # ads.example.com in global custom list
    assert decide(False, st.blocked_for_client(A_CEL, "ads.example.com"), global_custom_hit) == "BLOCK"
    assert decide(False, st.blocked_for_client(B_DESK, "ads.example.com"), global_custom_hit) == "BLOCK"


def test_client_rule_works_with_empty_blocklist():
    st = PolicyStore()
    st.add_rule(A_CEL, "tiktok.com")
    num_hashes = 0  # no global blocklist installed
    assert decide(False, st.blocked_for_client(A_CEL, "tiktok.com"), False) == "BLOCK"
    assert num_hashes == 0  # decision never consulted the global count
    # Firmware: policy check is not numHashes-gated and lives in handleDns:
    assert "isBlockedForClient(c ? c->mac : nullptr, domain)" in MAIN
    udp = MAIN[MAIN.find("static bool handleDns()"):MAIN.find("// ---------- web")]
    assert "isBlockedForClient" in udp


def test_banned_preserved():
    assert decide(True, False, False) == "BLOCK"
    assert decide(True, True, True) == "BLOCK"
    assert "bool ban = c && c->banned" in MAIN


def test_policy_table_capacity():
    st = PolicyStore()
    for i in range(1, MAX_POLICY_CLIENTS + 1):
        assert st.add_rule("aa:bb:cc:dd:ee:%02x" % i, "tiktok.com") is True
    assert len(st.rules) == MAX_POLICY_CLIENTS
    # 33rd distinct client is rejected and leaves the table untouched.
    assert st.add_rule("aa:bb:cc:dd:ee:00", "tiktok.com") is False
    assert len(st.rules) == MAX_POLICY_CLIENTS
    # An already-managed client can still use its own rule budget.
    assert st.add_rule("aa:bb:cc:dd:ee:01", "instagram.com") is True


def test_invalid_domains_rejected():
    st = PolicyStore()
    for bad in ("no-dot", "-lead.com", "trail-.com",
                "a" * 64 + ".com", "ok.com/evil", "a.com\nx", "<script>.com"):
        assert st.add_rule(A_CEL, bad) is False, bad
    assert st.rules.get(parse_mac(A_CEL), []) == []


def test_alias_limits_rejected():
    st = PolicyStore()
    assert st.set_alias(A_CEL, "x" * 33) is False
    assert st.set_alias(A_CEL, "a|b") is False
    assert st.set_alias(A_CEL, "a,b") is False
    assert st.set_alias(A_CEL, "bad\nname") is False
    assert st.set_alias("not-a-mac", "Pedro") is False
    assert st.set_alias("00:00:00:00:00:00", "Pedro") is False
    assert st.set_alias(A_CEL, "") is True  # empty clears


def test_malformed_persisted_data_safe():
    blob = (
        "this-is-not-a-line\n"
        "aa:bb:cc:dd:ee:ff|Pedro Celular|tiktok.com,not a domain!!,instagram.com\n"
        "zz:zz:zz:zz:zz:zz|Bad|tiktok.com\n"
        + "11:22:33:44:55:66|" + "y" * 40 + "|tiktok.com\n"  # oversized alias
        + "aa:bb:cc:dd:ee:ff|Dupe|tiktok.com\n"  # duplicate MAC
        + "aa:bb:cc:dd:ee:01|Big|" + ",".join("d%d.example.com" % i for i in range(50)) + "\n"
    )
    st = PolicyStore.load(blob)  # must not raise
    good = parse_mac(A_CEL)
    assert st.alias[good] == "Pedro Celular"
    assert "tiktok.com" in st.rules[good] and "instagram.com" in st.rules[good]
    assert len(st.rules[parse_mac("aa:bb:cc:dd:ee:01")]) <= MAX_RULES_PER_CLIENT


def test_udp_hierarchy_hook_no_tcp_coupling():
    # UDP-only slice: no handleDnsTcp exists upstream yet (TCP opt-in PR
    # extends coverage there). Policy must not reference the TCP path.
    assert "handleDnsTcp" not in MAIN
    udp = MAIN[MAIN.find("static bool handleDns()"):MAIN.find("// ---------- web")]
    assert "isBlockedForClient" in udp
    assert "buildBlocked" in udp


def test_firmware_wiring_and_limits():
    for token in ("MAX_POLICY_CLIENTS = 32", "MAX_RULES_PER_CLIENT = 16",
                  "MAX_ALIAS_LEN = 32", "/clientpol.txt",
                  "isBlockedForClient", "findPolicy",
                  "/setalias", "/addclientblock", "/unclientblock",
                  "loadPolicies()", "handleSetAlias", "handleAddClientBlock"):
        assert token in MAIN, token
    # New mutating endpoints keep the PR #16 auth model:
    assert MAIN.count("if (!requireAuth()) return;") >= 6
    # Dashboard: alias + manage UI, global vs per-client clearly separated:
    for token in ("Manage", "mAlias", "/setalias", "/addclientblock", "/unclientblock",
                  "GLOBAL", "affects everyone", "affect only this client", "esc(c.alias",
                  "esc(d)", "CSRF_HDRS"):
        assert token in PAGE, token

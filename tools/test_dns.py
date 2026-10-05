#!/usr/bin/env python3
"""Real DNS checks against a running device (requires `dig`).
Usage: python3 tools/test_dns.py 192.168.1.10

Covers item 8: A/AAAA sinkhole, TCP fallback, EDNS0, malformed handling.
Long-duration soak (item 6) and reboot-during-update (item 7) are procedures
documented below; they need hardware and are not automated here.
"""
import subprocess
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
BLOCKED = "doubleclick.net"
ALLOWED = "github.com"


def dig(*args):
    cmd = ["dig", f"@{TARGET}", *args, "+time=3", "+tries=1"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    return p.stdout + p.stderr


def check(name, cond, out):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        print(out[:2000])
    return cond


ok = True
out = dig(BLOCKED, "A")
ok &= check("blocked A -> 0.0.0.0", "0.0.0.0" in out, out)
out = dig(BLOCKED, "AAAA")
ok &= check("blocked AAAA -> :: (no IPv6 leak)", "::" in out and "NOERROR" in out, out)
out = dig(ALLOWED, "A")
ok &= check("allowed A forwarded (no 0.0.0.0)", "0.0.0.0" not in out, out)
out = dig(BLOCKED, "A", "+tcp")
ok &= check("blocked A over TCP -> 0.0.0.0", "0.0.0.0" in out, out)
out = dig(ALLOWED, "A", "+tcp")
ok &= check("allowed A over TCP forwarded", "0.0.0.0" not in out, out)
out = dig(ALLOWED, "A", "+dnssec", "+bufsize=1232")
ok &= check("EDNS0 bufsize=1232 answered", "status:" in out, out)
out = dig(ALLOWED, "MX")
ok &= check("MX passthrough (not sinkholed to 0.0.0.0)", "status:" in out, out)

print("\nSoak (item 6): point one client at the device for 12-24h, sample")
print("`dig @$IP github.com` every 60s, record heap via /stats.json hourly.")
print("Reboot-during-update (item 7): start a 500k-entry upload/fetch, cut")
print("power between renames; on boot the device must recover live/previous/new.")

sys.exit(0 if ok else 1)

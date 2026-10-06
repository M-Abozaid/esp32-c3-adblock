"""Input-policy tests mirroring the firmware validation in src/main.cpp.

Covers the auth-hardening slice: custom-domain hostname check and the
HTTPS-only update-URL policy (ALLOW_HTTP_BLOCKLIST opt-in). Any divergence
between these mirrors and the firmware is a bug in one of them; keep them
in sync when the validation changes.
Run: python -m pytest tests/test_input_policies.py -q
"""


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


def is_valid_update_url(u, allow_http=False):
    if not (8 <= len(u) <= 200):
        return False
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in u):
        return False
    if " " in u:
        return False
    if u.startswith("https://"):
        return True
    # Plain HTTP needs an explicit -DALLOW_HTTP_BLOCKLIST=1 build.
    return allow_http and u.startswith("http://")


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
    assert not is_valid_update_url("http://192.168.1.5/list.bin")
    assert is_valid_update_url("http://192.168.1.5/list.bin", allow_http=True)
    assert not is_valid_update_url("ftp://x/y")
    assert not is_valid_update_url("https://x\r\nHeader: evil")
    assert not is_valid_update_url("x" * 201)

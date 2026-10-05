#!/usr/bin/env python3
"""Refresh the pinned root CA bundle in src/certs.h.

The firmware pins a small static bundle (Arduino 2.x has no maintained
system bundle). Re-run this when GitHub/CDN rotates roots or yearly:

    python3 tools/refresh_certs.py --write

Then rebuild all targets and re-run the hardware TLS fetch test.
"""
import sys
import urllib.request

SOURCES = [
    "https://letsencrypt.org/certs/isrgrootx1.pem",
    "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem",
    "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem",
]
MARK_BEGIN = 'static const char ROOT_CA_BUNDLE[] PROGMEM = R"PEM('
MARK_END = ')PEM";'


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        text = r.read().decode("ascii")
    assert "-----BEGIN CERTIFICATE-----" in text, url
    return text.strip() + "\n"


def main():
    bundle = "".join(fetch(u) for u in SOURCES)
    if "--write" not in sys.argv:
        print(bundle)
        return
    path = "src/certs.h"
    src = open(path).read()
    pre, _, post = src.partition(MARK_BEGIN)
    _, _, post = post.partition(MARK_END)
    open(path, "w").write(pre + MARK_BEGIN + "\n" + bundle + MARK_END + post)
    print(f"refreshed {path} ({len(bundle)} bytes)")


if __name__ == "__main__":
    main()

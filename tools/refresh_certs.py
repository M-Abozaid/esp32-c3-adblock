#!/usr/bin/env python3
"""Refresh the pinned root CA bundle in src/certs.h.

The firmware pins a small static bundle (setCACert on all cores).
Re-run this when GitHub/CDN rotates roots or yearly:

    python3 tools/refresh_certs.py --write

Then rebuild all targets and re-run the hardware TLS fetch test.
Pinned set: ISRG Root X1 + DigiCert Global Root CA/G2 (authoritative
vendor URLs) + USERTrust RSA (Sectigo chain used by github.com,
extracted by label from the Mozilla bundle).
"""
import sys
import urllib.request

VENDOR_SOURCES = [
    "https://letsencrypt.org/certs/isrgrootx1.pem",
    "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem",
    "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt.pem",
]
MOZILLA_BUNDLE = "https://curl.se/ca/cacert.pem"
USERTrust_LABEL = "USERTrust RSA Certification Authority"
MARK_BEGIN = 'static const char ROOT_CA_BUNDLE[] PROGMEM = R"PEM('
MARK_END = ')PEM";'


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        text = r.read().decode("utf-8")
    assert "-----BEGIN CERTIFICATE-----" in text, url
    return text


def extract(bundle, label):
    idx = bundle.find(label)
    if idx < 0:
        raise SystemExit(f"label not found in bundle: {label}")
    start = bundle.find("-----BEGIN CERTIFICATE-----", idx)
    end = bundle.find("-----END CERTIFICATE-----", start)
    if start < 0 or end < 0:
        raise SystemExit(f"cert block not found for: {label}")
    return bundle[start:end + len("-----END CERTIFICATE-----")] + "\n"


def pem_block(text):
    start = text.find("-----BEGIN CERTIFICATE-----")
    end = text.find("-----END CERTIFICATE-----", start)
    if start < 0 or end < 0:
        raise SystemExit("no PEM block in fetched source")
    return text[start:end + len("-----END CERTIFICATE-----")] + "\n"


def main():
    bundle = "".join(pem_block(fetch(u)) for u in VENDOR_SOURCES)
    bundle += extract(fetch(MOZILLA_BUNDLE), USERTrust_LABEL)
    if "--write" not in sys.argv:
        print(bundle)
        return
    path = "src/certs.h"
    src = open(path).read()
    pre, sep, post = src.partition(MARK_BEGIN)
    if not sep:
        raise SystemExit(f"begin marker not found in {path}")
    _, sep2, post = post.partition(MARK_END)
    if not sep2:
        raise SystemExit(f"end marker not found in {path}")
    open(path, "w").write(pre + MARK_BEGIN + "\n" + bundle + MARK_END + post)
    print(f"refreshed {path} ({len(bundle)} bytes)")


if __name__ == "__main__":
    main()

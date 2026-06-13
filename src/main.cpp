// C3 AdBlock — a lean DNS sinkhole for the ESP32-C3 (no PSRAM needed).
// Blocklist = sorted 64-bit FNV-1a hashes in flash (LittleFS), binary-searched.
// Built from the idea of s60sc/ESP32_AdBlocker, but storing hashes in flash
// instead of domain strings in PSRAM — so it fits a $2 chip.
//
//   query in  -> extract domain -> FNV-1a + suffixes -> binary-search flash
//   blocked?  -> answer 0.0.0.0   (A) / NODATA (AAAA)
//   else      -> forward to upstream resolver, relay the reply

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>

// ---- config ----
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";
static const IPAddress UPSTREAM(9, 9, 9, 9);   // Quad9 (Swiss non-profit; privacy + malware filtering)
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";

// ---- globals ----
WiFiUDP dnsServer;   // listens on :53 for client queries
WiFiUDP upstreamCli; // forwards non-blocked queries upstream
File blocklist;      // sorted uint64 LE hash array in flash
uint32_t numHashes = 0;
uint32_t blockedCnt = 0, allowedCnt = 0;
uint8_t buf[600];    // DNS packets are small (UDP, <512 typical)

// 5-byte (40-bit) truncated FNV-1a — MUST match tools/build_blocklist.py.
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static uint64_t fnv1a64(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;               // truncate to HASH_BYTES
}

// Binary-search the flash hash array for h. ~20 cached reads, no RAM copy.
static bool hashInBlocklist(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1;
  uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    blocklist.seek((uint32_t)mid * HASH_BYTES);
    blocklist.read(b, HASH_BYTES);
    uint64_t v = 0;
    for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);   // little-endian
    if (v < h) lo = mid + 1;
    else if (v > h) hi = mid - 1;
    else return true;
  }
  return false;
}

// Block domain itself and any parent suffix down to 2 labels:
// "ads.doubleclick.net" also matches a listed "doubleclick.net".
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    if (hashInBlocklist(fnv1a64(p, strlen(p)))) return true;
    const char* dot = strchr(p, '.');
    if (!dot) break;
    const char* next = dot + 1;
    if (!strchr(next, '.')) break;   // stop at the registrable (2-label) suffix
    p = next;
  }
  return false;
}

// Extract the QNAME from a DNS query into `out` (lowercased, www. stripped to
// match preprocessing). Returns domain length, sets *qtype. 0 on parse error.
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;                 // compression pointer in a query: bail
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  *qend = i + 4;                            // end of question = start of answer
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}

// Turn the query in `buf` (qlen bytes) into a sinkhole response. Returns length.
static int buildBlocked(int qend, uint16_t qtype) {
  // Reply = header + question only (drop any EDNS OPT from additional), then
  // exactly one answer immediately after the question.
  buf[2] = 0x81; buf[3] = 0x80;              // QR=1, RD=1, RA=1, RCODE=0
  buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; // ANCOUNT (1 for A, else NODATA)
  buf[8] = 0; buf[9] = 0;                     // NSCOUNT = 0
  buf[10] = 0; buf[11] = 0;                   // ARCOUNT = 0 (strip EDNS OPT)
  if (qtype != 1) return qend;               // non-A -> NODATA
  const uint8_t ans[] = {0xC0,0x0C, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x01,0x2C,
                         0x00,0x04, 0x00,0x00,0x00,0x00};   // ptr,A,IN,TTL300,len4,0.0.0.0
  memcpy(buf + qend, ans, sizeof(ans));
  return qend + sizeof(ans);
}

// Forward query (qlen bytes in buf) to upstream, relay reply into buf. Returns len or 0.
static int forwardUpstream(int qlen) {
  upstreamCli.beginPacket(UPSTREAM, 53);
  upstreamCli.write(buf, qlen);
  upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 1500) {
    int sz = upstreamCli.parsePacket();
    if (sz > 0) { int n = upstreamCli.read(buf, sizeof(buf)); return n; }
    delay(1);
  }
  return 0;   // upstream timeout
}

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n[c3-adblock] booting");

  if (!LittleFS.begin(true)) { Serial.println("LittleFS mount FAILED"); }
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (!blocklist) Serial.println("!! blocklist.bin missing — run `pio run -t uploadfs`");
  else { numHashes = blocklist.size() / HASH_BYTES; Serial.printf("blocklist: %u domains (%u bytes)\n", numHashes, (uint32_t)blocklist.size()); }

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);   // disable modem power-save -> much lower DNS latency
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("WiFi: joining %s", WIFI_SSID);
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
  Serial.printf("\nWiFi up: %s  -> point a client's DNS here to block ads\n", WiFi.localIP().toString().c_str());

  if (MDNS.begin("c3adblock")) Serial.println("mDNS: reachable at c3adblock.local");

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(0);   // ephemeral local port
  Serial.println("DNS sinkhole listening on :53");
}

void loop() {
  int sz = dnsServer.parsePacket();
  if (sz <= 0) { delay(1); return; }
  IPAddress cip = dnsServer.remoteIP();
  uint16_t cport = dnsServer.remotePort();
  int qlen = dnsServer.read(buf, sizeof(buf));
  if (qlen < 13) return;

  char domain[256]; uint16_t qtype = 0; int qend = qlen;
  size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);

  int rlen;
  bool blocked = dl && numHashes && isBlocked(domain);
  if (blocked) { rlen = buildBlocked(qend, qtype); blockedCnt++; }
  else         { rlen = forwardUpstream(qlen);     allowedCnt++; }

  if (rlen > 0) {
    dnsServer.beginPacket(cip, cport);
    dnsServer.write(buf, rlen);
    dnsServer.endPacket();
  }
  Serial.printf("%s  %s   [blocked %u / allowed %u]\n",
                blocked ? "BLOCK" : "fwd  ", dl ? domain : "(parse?)", blockedCnt, allowedCnt);
}

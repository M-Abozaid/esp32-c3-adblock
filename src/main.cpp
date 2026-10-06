// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

// ---- DNS query logging (opt-in) ----
// Build with -DENABLE_QUERY_LOGGING=1 to emit fire-and-forget binary UDP
// telemetry of DNS decisions to a collector. Default OFF: the event queue
// and all logging code compile out, so builds reserve zero RAM for it.
#ifndef ENABLE_QUERY_LOGGING
#define ENABLE_QUERY_LOGGING 0
#endif
#if ENABLE_QUERY_LOGGING
#include <time.h>  // event timestamps (0 = clock not synced yet)
#endif

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
#if ENABLE_QUERY_LOGGING
WiFiUDP dnsLogUdp;
#endif
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

#if ENABLE_QUERY_LOGGING
// ---------- DNS query logging via UDP collector (opt-in telemetry) ----------
// Principles: DNS never depends on the collector. Disabled by default.
// Fire-and-forget binary UDP, best-effort, no retry, no persistent queue,
// no LittleFS history, no database. Loss is acceptable. The collector is a
// separate project; the ESP32 only decides and emits.
//
// Wire format v1 (big-endian multi-byte, total 34 + domain_length, max 287):
//   Offset Size  Field
//   0      1     Protocol version (1)
//   1      1     Event type (0x01 = DNS_QUERY)
//   2      4     Sequence number (uint32, wraps, RAM only, never persisted)
//   6      4     Timestamp unix (0 = clock not synced yet, never blocks DNS)
//   10     6     Device ID (logical Lily identity for v1; derived from
//                the ESP32 STA MAC and stable for the lifetime of the
//                device. Lets one collector serve many Lilys; not a
//                hostname, decoupled from any future logical naming.)
//   16     6     Client MAC (primary identity, survives DHCP changes;
//                all zeros = unknown, never blocks the query)
//   22     4     Client IPv4 (complementary, dotted order; the address
//                observed at that moment, not the identity)
//   26     2     QTYPE (full numeric DNS type, e.g. 1 = A, 28 = AAAA,
//                15 = MX; preserved, never coerced to A/AAAA)
//   28     1     RCODE actually delivered to the client: v1 records the
//                4-bit DNS header RCODE; extended EDNS RCODE is not
//                represented. Values: 0 NOERROR, 1 FORMERR, 2 SERVFAIL,
//                3 NXDOMAIN, 5 REFUSED.
//                Locally blocked sinkhole/NODATA replies always carry 0.
//                Upstream failures with no reply emit no event (never
//                invent a code, never mislabel a failure as blocked).
//   29     2     Latency ms (query-received -> response-ready/sent,
//                saturated at 0xFFFF; collector UDP time never included)
//   31     1     Transport of the original DNS query (0 = UDP, 1 = TCP;
//                not the telemetry transport)
//   32     1     Flags (bit0 = blocked, bit1 = response generated locally;
//                blocked lives here, not as a separate field)
//   33     1     Domain length N (1..253)
//   34     N     Domain (normalized DNS name only, never URL/HTTPS content)
// No credentials, cookies, configs or commands ever travel this channel,
// and inbound UDP on the logging socket is never interpreted.
static const uint8_t DNSLOG_VERSION = 1;
static const uint8_t DNSLOG_EVENT_DNS_QUERY = 0x01;
static const size_t DNSLOG_MAX_DOMAIN = 253;
static const size_t DNSLOG_PKT_HEAD = 34;
static const size_t DNSLOG_MAX_PKT = 34 + 253;  // 287
static const int DNSLOG_QUEUE_CAP = 32;         // small RAM queue; full -> drop
static const uint16_t DNSLOG_DEFAULT_PORT = 40153;
static const size_t DNSLOG_MAX_HOST_LEN = 64;   // v1: IPv4 dotted string only
static const char* DNSLOG_CFG_PATH = "/dnslog.cfg";
static const uint8_t DNSLOG_TRANSPORT_UDP = 0;
static const uint8_t DNSLOG_TRANSPORT_TCP = 1;
static const uint16_t DNSLOG_LATENCY_MAX = 0xFFFF;  // saturation, not a timeout
// Mode: 0 = OFF, 1 = BLOCKED_ONLY, 2 = ALL. Without Enable the effective
// mode is OFF (see dnsLoggingActive()).
static bool dnslogEnabled = false;
static char dnslogHost[65] = "";
static uint16_t dnslogPort = DNSLOG_DEFAULT_PORT;
static uint8_t dnslogMode = 0;
static IPAddress dnslogIP;
static bool dnslogHaveIP = false;
static uint32_t dnsLogSequence = 0;   // wraps; RAM only, never persisted
static uint32_t dnsLogGenerated = 0, dnsLogDispatched = 0, dnsLogDropped = 0;
static uint32_t dnsLogLastUnix = 0;   // unix time of last dispatched event (0 = none)
static uint8_t dnsDeviceId[6] = {0, 0, 0, 0, 0, 0};  // STA MAC, captured once at setup
struct DnsLogSlot { uint8_t pkt[34 + 253]; uint16_t len; uint32_t unix; };
static DnsLogSlot dnsLogQueue[DNSLOG_QUEUE_CAP];
static int dnsLogHead = 0, dnsLogTail = 0, dnsLogCount = 0;
static const char* dnsLogModeStr() { return dnslogMode == 1 ? "BLOCKED_ONLY" : dnslogMode == 2 ? "ALL" : "OFF"; }
// v1 accepts IPv4 only: no per-query DNS resolution of the collector name,
// the cached address is resolved once at load/save time and reused.
static bool dnsLogHostValid(const String& h) {
  if (h.length() == 0 || h.length() > DNSLOG_MAX_HOST_LEN) return false;
  for (size_t i = 0; i < h.length(); i++) {
    char c = h[i];
    if (c < 0x20 || c == 0x7F || c == ' ') return false;
  }
  IPAddress ip;
  return ip.fromString(h);
}
// Latency is measured strictly as query-received -> response-ready/sent.
// The enqueue below and the UDP send in dnsLogPump() happen after the
// measurement, so collector time can never inflate latency_ms. Saturates
// instead of overflowing; never adds artificial delay to DNS.
static uint16_t dnsLogLatency(uint32_t t0ms, uint32_t t1ms) {
  uint32_t d = t1ms - t0ms;  // millis() wrap-safe unsigned difference
  return d > DNSLOG_LATENCY_MAX ? DNSLOG_LATENCY_MAX : (uint16_t)d;
}
static uint32_t dnsLogNowUnix() {
  time_t t = time(nullptr);
  if (t < (time_t)1704067200 || t < 0) return 0;  // clock not synced: mark invalid, never block DNS on NTP
  return (uint32_t)t;
}
static bool dnsLoggingActive() { return dnslogEnabled && dnslogMode != 0 && dnslogHaveIP && dnslogPort != 0; }
static bool dnsLogShouldSend(bool blocked) {
  if (!dnsLoggingActive()) return false;
  if (dnslogMode == 1) return blocked;   // BLOCKED_ONLY
  if (dnslogMode == 2) return true;      // ALL
  return false;
}
// Encodes one event into out; returns total length or 0 when the domain is
// out of bounds or the buffer is too small. Never reads past domain[domainLen].
static size_t dnsLogEncode(uint8_t* out, size_t outCap, uint32_t seq, uint32_t nowUnix,
                           const uint8_t* deviceId, const uint8_t* mac, IPAddress cip,
                           uint16_t qtype, uint8_t rcode, uint16_t latencyMs,
                           uint8_t transport, bool blocked,
                           const char* domain, size_t domainLen) {
  if (!out || !domain || domainLen == 0 || domainLen > DNSLOG_MAX_DOMAIN) return 0;
  if (outCap < DNSLOG_PKT_HEAD + domainLen) return 0;
  if (transport != DNSLOG_TRANSPORT_UDP && transport != DNSLOG_TRANSPORT_TCP) return 0;
  out[0] = DNSLOG_VERSION;
  out[1] = DNSLOG_EVENT_DNS_QUERY;
  out[2] = (uint8_t)(seq >> 24); out[3] = (uint8_t)(seq >> 16);
  out[4] = (uint8_t)(seq >> 8);  out[5] = (uint8_t)seq;
  out[6] = (uint8_t)(nowUnix >> 24); out[7] = (uint8_t)(nowUnix >> 16);
  out[8] = (uint8_t)(nowUnix >> 8);  out[9] = (uint8_t)nowUnix;
  if (deviceId) memcpy(out + 10, deviceId, 6); else memset(out + 10, 0, 6);
  if (mac) memcpy(out + 16, mac, 6); else memset(out + 16, 0, 6);
  out[22] = cip[0]; out[23] = cip[1]; out[24] = cip[2]; out[25] = cip[3];
  out[26] = (uint8_t)(qtype >> 8); out[27] = (uint8_t)qtype;
  out[28] = (uint8_t)(rcode & 0x0F);
  out[29] = (uint8_t)(latencyMs >> 8); out[30] = (uint8_t)latencyMs;
  out[31] = transport;
  out[32] = (uint8_t)((blocked ? 0x01 : 0x00) | (blocked ? 0x02 : 0x00));  // bit0 blocked, bit1 locally generated (sinkhole)
  out[33] = (uint8_t)domainLen;
  memcpy(out + 34, domain, domainLen);
  return DNSLOG_PKT_HEAD + domainLen;
}
static void dnsLogResolve() {
  IPAddress ip;
  if (dnslogHost[0] && ip.fromString(String(dnslogHost))) { dnslogIP = ip; dnslogHaveIP = true; }
  else dnslogHaveIP = false;
}
// Enqueue only; the actual UDP send happens in dnsLogPump() from loop() so
// the DNS path never blocks on the network. Queue full -> drop the event.
// rcode/latency/transport must come from the already-finished DNS exchange:
// callers pass the code actually delivered, the measured processing time,
// and the transport the query arrived on. No reply (rlen == 0) -> caller
// skips the emit; this function never invents a result.
static void dnsLogEmit(const uint8_t* mac, IPAddress cip, const char* domain,
                       uint16_t qtype, bool blocked, uint8_t rcode,
                       uint16_t latencyMs, uint8_t transport) {
  if (!dnsLogShouldSend(blocked)) return;
  if (!domain) return;
  size_t dlen = strlen(domain);
  dnsLogGenerated++;
  if (dlen == 0 || dlen > DNSLOG_MAX_DOMAIN) { dnsLogDropped++; return; }  // oversized: discard locally
  uint8_t tmp[34 + 253];
  uint8_t m[6] = {0, 0, 0, 0, 0, 0};
  if (mac) memcpy(m, mac, 6);
  uint32_t nowUnix = dnsLogNowUnix();
  size_t plen = dnsLogEncode(tmp, sizeof(tmp), dnsLogSequence + 1, nowUnix,
                             dnsDeviceId, m, cip, qtype, rcode, latencyMs,
                             transport, blocked, domain, dlen);
  if (!plen) { dnsLogDropped++; return; }
  dnsLogSequence++;  // consume a sequence number only for a well-formed event
  if (dnsLogCount >= DNSLOG_QUEUE_CAP) { dnsLogDropped++; return; }
  DnsLogSlot* s = &dnsLogQueue[dnsLogTail];
  memcpy(s->pkt, tmp, plen);
  s->len = (uint16_t)plen;
  s->unix = nowUnix;
  dnsLogTail = (dnsLogTail + 1) % DNSLOG_QUEUE_CAP;
  dnsLogCount++;
}
// Best-effort drain: a few datagrams per loop call so TCP/DNS/dashboard/OTA
// keep their turn. Any send failure is a silent drop — never a retry, never
// a DNS error, never persisted.
static void dnsLogPump() {
  for (int budget = 0; budget < 8 && dnsLogCount > 0; budget++) {
    DnsLogSlot* s = &dnsLogQueue[dnsLogHead];
    uint16_t len = s->len;
    uint32_t unix = s->unix;
    uint8_t pkt[34 + 253];
    if (len > sizeof(pkt)) { dnsLogDropped++; }
    else {
      memcpy(pkt, s->pkt, len);
      dnsLogHead = (dnsLogHead + 1) % DNSLOG_QUEUE_CAP;
      dnsLogCount--;
      bool ok = false;
      if (dnslogHaveIP && dnslogPort != 0) {
        dnsLogUdp.beginPacket(dnslogIP, dnslogPort);
        dnsLogUdp.write(pkt, len);
        ok = dnsLogUdp.endPacket() != 0;
      }
      if (ok) { dnsLogDispatched++; dnsLogLastUnix = unix; }
      else dnsLogDropped++;
      continue;
    }
    dnsLogHead = (dnsLogHead + 1) % DNSLOG_QUEUE_CAP;
    dnsLogCount--;
  }
}
static void saveDnsLog() {
  File f = LittleFS.open(DNSLOG_CFG_PATH, "w"); if (!f) return;
  f.println(dnslogEnabled ? "1" : "0");
  f.println(dnslogHost);
  f.println(dnslogPort);
  f.println(dnsLogModeStr());
  f.close();
}
// Invalid persisted config -> logging disabled, firmware continues normally.
static void loadDnsLog() {
  dnslogEnabled = false; dnslogHost[0] = 0; dnslogPort = DNSLOG_DEFAULT_PORT;
  dnslogMode = 0; dnslogHaveIP = false;
  File f = LittleFS.open(DNSLOG_CFG_PATH, "r"); if (!f) return;
  String en = f.readStringUntil('\n'); en.trim();
  String host = f.readStringUntil('\n'); host.trim();
  String portS = f.readStringUntil('\n'); portS.trim();
  String modeS = f.readStringUntil('\n'); modeS.trim(); modeS.toUpperCase();
  f.close();
  if (en != "0" && en != "1") return;  // corrupt: stay disabled
  long port = portS.toInt();
  if (port < 1 || port > 65535) return;  // corrupt: stay disabled
  uint8_t mode = 0;
  if (modeS == "OFF" || modeS == "0") mode = 0;
  else if (modeS == "BLOCKED_ONLY" || modeS == "1") mode = 1;
  else if (modeS == "ALL" || modeS == "2") mode = 2;
  else return;  // unknown enum: stay disabled
  if (host.length() > DNSLOG_MAX_HOST_LEN) return;
  if (host.length() && !dnsLogHostValid(host)) return;  // bad host: stay disabled
  if (en == "1" && mode != 0 && host.length() == 0) return;  // enabled needs a host
  dnslogEnabled = (en == "1");
  if (host.length()) { strncpy(dnslogHost, host.c_str(), sizeof(dnslogHost) - 1); dnslogHost[sizeof(dnslogHost) - 1] = 0; }
  dnslogPort = (uint16_t)port;
  dnslogMode = mode;
  dnsLogResolve();
  // Note: the host string is kept for display even when inactive;
  // dnsLoggingActive() gates every send, so an invalid/disabled config
  // can never emit.
}
#endif  // ENABLE_QUERY_LOGGING

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
#if ENABLE_QUERY_LOGGING
    uint32_t qMs = millis();  // latency start: query received off the wire
#endif
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
    int rlen;
#if ENABLE_QUERY_LOGGING
    uint8_t rcode = 0;
    if (blocked) { rlen = buildBlocked(qend, qtype); rcode = 0; totalBlocked++; if (c) c->blocked++; }  // sinkhole/NODATA replies always carry NOERROR
    else         { rlen = forwardUpstream(qlen, qend); if (rlen >= 12) rcode = buf[3] & 0x0F; totalAllowed++; if (c) c->allowed++; }
#else
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen, qend);     totalAllowed++; if (c) c->allowed++; }
#endif
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
#if ENABLE_QUERY_LOGGING
    // Telemetry last: reply already on the wire, latency stops here, the
    // collector UDP send happens later in dnsLogPump(). Upstream timeout
    // (rlen == 0, nothing delivered) emits nothing — never invent a code.
    if (rlen > 0)
      dnsLogEmit(c ? c->mac : nullptr, cip, domain, qtype, blocked, rcode,
                 dnsLogLatency(qMs, millis()), DNSLOG_TRANSPORT_UDP);
#endif
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
#if ENABLE_QUERY_LOGGING
  j += "],\"dnslog\":{\"enabled\":" + String(dnslogEnabled ? "true" : "false") +
       ",\"mode\":\"" + dnsLogModeStr() + "\"" +
       ",\"device\":\"" + macStr(dnsDeviceId) + "\"" +
       ",\"host\":\"" + jesc(String(dnslogHost)) + "\"" +
       ",\"port\":" + dnslogPort +
       ",\"active\":" + (dnsLoggingActive() ? "true" : "false") +
       ",\"generated\":" + dnsLogGenerated +
       ",\"dispatched\":" + dnsLogDispatched +
       ",\"dropped\":" + dnsLogDropped +
       ",\"last\":" + dnsLogLastUnix + "}";
#endif
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}
#if ENABLE_QUERY_LOGGING
// DNS logging config endpoint. Same auth model as /ban and /addblock.
// Args: enabled=0/1, host=<ipv4>, port=1..65535, mode=OFF|BLOCKED_ONLY|ALL.
// v1 accepts IPv4 only so no collector DNS lookup ever happens on the device.
static void handleSetDnsLog() {
  if (!requireAuth()) return;
  bool newEnabled = dnslogEnabled;
  String newHost = String(dnslogHost);
  long newPort = dnslogPort;
  uint8_t newMode = dnslogMode;
  if (web.hasArg("enabled")) {
    String e = web.arg("enabled"); e.trim(); e.toLowerCase();
    if (e == "1" || e == "true" || e == "on") newEnabled = true;
    else if (e == "0" || e == "false" || e == "off") newEnabled = false;
    else { web.send(400, "text/plain", "invalid enabled (0/1)"); return; }
  }
  if (web.hasArg("host")) {
    newHost = web.arg("host"); newHost.trim();
    if (newHost.length() > (int)DNSLOG_MAX_HOST_LEN) { web.send(400, "text/plain", "invalid host (max 64 chars, IPv4)"); return; }
    if (newHost.length() && !dnsLogHostValid(newHost)) { web.send(400, "text/plain", "invalid host (IPv4 required)"); return; }
  }
  if (web.hasArg("port")) {
    newPort = web.arg("port").toInt();
    if (newPort < 1 || newPort > 65535) { web.send(400, "text/plain", "invalid port (1..65535)"); return; }
  }
  if (web.hasArg("mode")) {
    String m = web.arg("mode"); m.trim(); m.toUpperCase();
    if (m == "OFF" || m == "0") newMode = 0;
    else if (m == "BLOCKED_ONLY" || m == "1") newMode = 1;
    else if (m == "ALL" || m == "2") newMode = 2;
    else { web.send(400, "text/plain", "invalid mode (OFF/BLOCKED_ONLY/ALL)"); return; }
  }
  if (newEnabled && newMode != 0 && newHost.length() == 0) { web.send(400, "text/plain", "host required when enabled"); return; }
  dnslogEnabled = newEnabled;
  memset(dnslogHost, 0, sizeof(dnslogHost));
  if (newHost.length()) { strncpy(dnslogHost, newHost.c_str(), sizeof(dnslogHost) - 1); }
  dnslogPort = (uint16_t)newPort;
  dnslogMode = newMode;
  dnsLogResolve();
  saveDnsLog();
  web.send(200, "text/plain", "ok");
}
#endif  // ENABLE_QUERY_LOGGING

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadUpdateCfg();
#if ENABLE_QUERY_LOGGING
  loadDnsLog();
#endif
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
#if ENABLE_QUERY_LOGGING
  WiFi.macAddress(dnsDeviceId);  // stable per-device telemetry identity (not a hostname, no config needed)
#endif
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
#if ENABLE_QUERY_LOGGING
  dnsLogUdp.begin(0);
#endif
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
#if ENABLE_QUERY_LOGGING
  web.on("/setdnslog", handleSetDnsLog);
#endif
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
#if ENABLE_QUERY_LOGGING
  dnsLogPump();  // fire-and-forget drain; never blocks DNS, never retries
#endif
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}

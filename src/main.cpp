// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, per-client aliases/policies, add custom block domains.
// All control state persisted to flash.

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
#include <time.h>              // NTP time for TLS certificate validation
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "hardware/hardware.h"  // observability only; DNS never depends on it
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)
#include "certs.h"     // ROOT_CA_BUNDLE for validated HTTPS blocklist downloads

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
// Versioned blocklist header (16 bytes, little-endian):
//   magic[4] = 'C','A','D','B', version u16 = 1, hashBytes u8,
//   reserved u8, count u32, crc32 u32 of payload.
// Legacy files without a header (flat size % 5 == 0) are still accepted.
static const uint16_t BLOCKLIST_VERSION = 1;
static const size_t BLOCKLIST_HEADER_SIZE = 16;
static uint32_t blocklistOffset = 0;

static uint32_t crc32Update(uint32_t crc, const uint8_t* data, size_t len) {
  crc = ~crc;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int k = 0; k < 8; k++)
      crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
  }
  return ~crc;
}
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, upstreamCli, dnsLogUdp;
WiFiServer dnsTcp(DNS_PORT);
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

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; uint32_t qWindowMs; uint16_t qCount; };
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
    blocklist.seek(blocklistOffset + (uint32_t)pos * HASH_BYTES);
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

  blocklist.seek(blocklistOffset + (uint32_t)startPos * HASH_BYTES);
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

// ---------- input validation (firmware-side; never trust browser JS) ----------
static bool hasControlChars(const String& s) {
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c < 0x20 || c == 0x7F) return true;
  }
  return false;
}
// Reasonable hostname check: labels of [a-z0-9-], 1..63 chars, no leading or
// trailing hyphen, 1..253 total, at least one dot. Rejects HTML/JS/control
// payloads without breaking legitimate hostnames.
static bool isValidDomain(String d) {
  d.trim(); d.toLowerCase();
  if (d.startsWith("www.")) d = d.substring(4);
  if (d.length() < 3 || d.length() > 253) return false;
  if (hasControlChars(d)) return false;
  if (d.indexOf('.') < 0) return false;
  int labels = 0, len = 0;
  for (size_t i = 0; i <= d.length(); i++) {
    char c = i < d.length() ? d[i] : '.';
    if (c == '.') {
      if (len < 1 || len > 63) return false;
      labels++; len = 0;
    } else {
      bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
      if (!ok) return false;
      if (c == '-' && (len == 0 || i + 1 >= d.length() || d[i + 1] == '.')) return false;
      if (++len > 63) return false;
    }
  }
  return labels >= 2;
}
// Update URL policy: HTTPS only by default. Plain HTTP would let a LAN
// attacker replace the blocklist (CRC32 cannot detect that), so it is
// rejected unless the build explicitly opts in with -DALLOW_HTTP_BLOCKLIST=1
// for isolated LAN testing. Private/LAN hosts are allowed because only an
// authenticated admin can set the URL (documented SSRF surface).
static bool isValidUpdateUrl(const String& u) {
  if (u.length() < 8 || u.length() > 200) return false;
  if (hasControlChars(u)) return false;
  if (u.indexOf(' ') >= 0) return false;
#ifdef ALLOW_HTTP_BLOCKLIST
  return u.startsWith("https://") || u.startsWith("http://");
#else
  return u.startsWith("https://");
#endif
}
// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (isValidDomain(l)) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!isValidDomain(d) || numCustom >= MAX_CUSTOM) return false;
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
// ---------- per-client domain policies ----------
static String macStr(const uint8_t* m);  // defined in the web section below
// Identity: MAC address resolved via ARP (see getMac). The DNS path only uses
// the IP to find the current MAC; rules are keyed by MAC so DHCP renewals
// keep working. A zero MAC (no ARP entry) gets no per-client rules.
// Limitation: Wi-Fi MAC randomization (private address per network) creates a
// new identity; policies follow the randomized MAC until the client resets it.
static const int MAX_POLICY_CLIENTS = 32;
static const int MAX_RULES_PER_CLIENT = 16;
static const int MAX_ALIAS_LEN = 32;
struct ClientPolicy { uint8_t mac[6]; bool used; String alias; String rule[MAX_RULES_PER_CLIENT]; uint64_t ruleHash[MAX_RULES_PER_CLIENT]; int ruleCount; };
static ClientPolicy policies[MAX_POLICY_CLIENTS];
static inline bool macIsZero(const uint8_t* m) { for (int i = 0; i < 6; i++) if (m[i]) return false; return true; }
static inline bool macEq(const uint8_t* a, const uint8_t* b) { for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false; return true; }
// Strict aa:bb:cc:dd:ee:ff (accepts upper case, stores lower). Rejects
// anything else so a crafted ?mac= can never address another client.
static bool parseMac(const String& s, uint8_t* out) {
  if (s.length() != 17) return false;
  for (int i = 0; i < 17; i++) {
    char c = s[i];
    if (i % 3 == 2) { if (c != ':') return false; continue; }
    bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!hex) return false;
  }
  auto nib = [](char c) -> uint8_t { return (uint8_t)(c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10)); };
  for (int i = 0; i < 6; i++) out[i] = (uint8_t)((nib(s[i * 3]) << 4) | nib(s[i * 3 + 1]));
  return true;
}
// Alias is metadata only: 0..32 chars (empty clears), no control chars, and
// none of the persistence delimiters ('|', ',', newline). Everything else is
// allowed and HTML/JSON-escaped on render.
static bool isValidAlias(const String& a) {
  if (a.length() > (size_t)MAX_ALIAS_LEN) return false;
  if (hasControlChars(a)) return false;
  if (a.indexOf('|') >= 0 || a.indexOf(',') >= 0 || a.indexOf('\n') >= 0 || a.indexOf('\r') >= 0) return false;
  return true;
}
static ClientPolicy* findPolicy(const uint8_t* mac) {
  if (!mac || macIsZero(mac)) return nullptr;
  for (int i = 0; i < MAX_POLICY_CLIENTS; i++)
    if (policies[i].used && macEq(policies[i].mac, mac)) return &policies[i];
  return nullptr;
}
static ClientPolicy* findOrCreatePolicy(const uint8_t* mac) {
  ClientPolicy* p = findPolicy(mac);
  if (p || !mac || macIsZero(mac)) return p;
  for (int i = 0; i < MAX_POLICY_CLIENTS; i++)
    if (!policies[i].used) {
      policies[i].used = true; memcpy(policies[i].mac, mac, 6);
      policies[i].alias = ""; policies[i].ruleCount = 0;
      return &policies[i];
    }
  return nullptr;  // table full: reject, never evict managed policies silently
}
static void savePolicies() {
  File f = LittleFS.open("/clientpol.tmp", "w"); if (!f) return;
  for (int i = 0; i < MAX_POLICY_CLIENTS; i++) {
    if (!policies[i].used) continue;
    f.print(macStr(policies[i].mac)); f.print('|'); f.print(policies[i].alias); f.print('|');
    for (int j = 0; j < policies[i].ruleCount; j++) { if (j) f.print(','); f.print(policies[i].rule[j]); }
    f.println();
  }
  f.close();
  LittleFS.remove("/clientpol.txt");
  LittleFS.rename("/clientpol.tmp", "/clientpol.txt");
}
static void loadPolicies() {
  for (int i = 0; i < MAX_POLICY_CLIENTS; i++) { policies[i].used = false; policies[i].alias = ""; policies[i].ruleCount = 0; }
  File f = LittleFS.open("/clientpol.txt", "r"); if (!f) return;
  int slot = 0;
  while (f.available() && slot < MAX_POLICY_CLIENTS) {
    String line = f.readStringUntil('\n');
    if (line.length() > 2048) continue;  // corrupt/oversized line: skip, never crash
    int p1 = line.indexOf('|'); int p2 = line.indexOf('|', p1 + 1);
    if (p1 < 0 || p2 < 0) continue;
    String macS = line.substring(0, p1); String alias = line.substring(p1 + 1, p2); String rules = line.substring(p2 + 1);
    uint8_t mac[6];
    if (!parseMac(macS, mac) || macIsZero(mac)) continue;
    if (!isValidAlias(alias)) continue;
    if (findPolicy(mac)) continue;  // duplicate MAC in file: keep first
    ClientPolicy* p = findOrCreatePolicy(mac);
    if (!p) break;
    p->alias = alias;
    int start = 0;
    while (start <= rules.length() && p->ruleCount < MAX_RULES_PER_CLIENT) {
      int c = rules.indexOf(',', start);
      String d = (c < 0 ? rules.substring(start) : rules.substring(start, c));
      d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
      bool dup = false;
      for (int k = 0; k < p->ruleCount; k++) if (p->rule[k] == d) { dup = true; break; }
      if (!dup && isValidDomain(d)) {
        p->rule[p->ruleCount] = d; p->ruleHash[p->ruleCount] = fnv40(d.c_str(), d.length()); p->ruleCount++;
      } else if (!dup && d.length() == 0) {
        // trailing comma: nothing to add
      }
      // invalid entries are skipped individually; the rest of the line still loads
      if (c < 0) break;
      start = c + 1;
    }
    slot++;
  }
  f.close();
}
static bool setClientAlias(const String& macS, String alias) {
  uint8_t mac[6];
  if (!parseMac(macS, mac) || macIsZero(mac)) return false;
  alias.trim();
  if (!isValidAlias(alias)) return false;
  ClientPolicy* p = findOrCreatePolicy(mac);
  if (!p) return false;
  p->alias = alias; savePolicies(); return true;
}
static bool addClientRule(String macS, String d) {
  uint8_t mac[6]; macS.trim();
  if (!parseMac(macS, mac) || macIsZero(mac)) return false;
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!isValidDomain(d)) return false;
  ClientPolicy* p = findOrCreatePolicy(mac);
  if (!p || p->ruleCount >= MAX_RULES_PER_CLIENT) return false;
  for (int i = 0; i < p->ruleCount; i++) if (p->rule[i] == d) return false;
  p->rule[p->ruleCount] = d; p->ruleHash[p->ruleCount] = fnv40(d.c_str(), d.length()); p->ruleCount++;
  savePolicies(); return true;
}
static bool removeClientRule(const String& macS, String d) {
  uint8_t mac[6];
  if (!parseMac(macS, mac) || macIsZero(mac)) return false;
  d.trim(); d.toLowerCase();
  ClientPolicy* p = findPolicy(mac);
  if (!p) return false;
  for (int i = 0; i < p->ruleCount; i++) if (p->rule[i] == d) {
    for (int j = i; j < p->ruleCount - 1; j++) { p->rule[j] = p->rule[j + 1]; p->ruleHash[j] = p->ruleHash[j + 1]; }
    p->ruleCount--; savePolicies(); return true;
  }
  return false;
}
// Same suffix-walk semantics as isBlocked(): rule tiktok.com matches
// tiktok.com and www/api/m.tiktok.com, but never notiktok.com (hash differs
// and the walk only strips at dot boundaries). Only this client's small rule
// set is scanned, so there is no clients x rules scan per query.
static bool isBlockedForClient(const uint8_t* mac, const char* domain) {
  ClientPolicy* p = findPolicy(mac);
  if (!p || p->ruleCount == 0) return false;
  const char* q = domain;
  while (q && *q) {
    uint64_t h = fnv40(q, strlen(q));
    for (int i = 0; i < p->ruleCount; i++) if (p->ruleHash[i] == h) return true;
    const char* dot = strchr(q, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; q = next;
  }
  return false;
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

// ---------- DNS query logging via UDP collector (PR #19, optional telemetry) ----------
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

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) {
    clients[i].lastSeen = millis();
    // ARP may have resolved after entry creation: fill in a previously
    // unknown MAC so per-client policy starts applying. Never overwrites
    // a known MAC.
    if (macIsZero(clients[i].mac)) getMac(ip, clients[i].mac);
    return &clients[i];
  }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = ""; c->qWindowMs = 0; c->qCount = 0;
    getMac(ip, c->mac); return c;
  }
  // Table full: evict the least-recently-seen client so one scanner cannot
  // pin the table while per-IP rate limiting keeps working.
  int oldest = 0;
  for (int i = 1; i < numClients; i++)
    if ((int32_t)(clients[i].lastSeen - clients[oldest].lastSeen) < 0) oldest = i;
  Dev* c = &clients[oldest];
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = ""; c->qWindowMs = 0; c->qCount = 0;
  getMac(ip, c->mac); return c;
}

// Flood protection policy (documented, tunable at compile time):
// Home clients burst (browser/DNS prefetch, Android, TVs, consoles), so the
// limit is a 1-second sliding window, not a hard per-burst cap. Over-limit
// queries are dropped without a reply: the client times out and retries,
// while the DNS task stays responsive for everyone else. Increase for very
// busy networks, decrease for weak upstreams.
#ifndef DNS_MAX_QPS
#define DNS_MAX_QPS 50
#endif
static bool allowQuery(Dev* c) {
  if (!c) return true;
  uint32_t now = millis();
  if (now - c->qWindowMs >= 1000) { c->qWindowMs = now; c->qCount = 0; }
  if (c->qCount >= DNS_MAX_QPS) return false;
  c->qCount++;
  return true;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1];
  uint16_t qclass = (pkt[i + 2] << 8) | pkt[i + 3];
  if (qclass != 1) return 0;  // IN class only; reject CHAOS/Hesiod and garbage
  *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
// Sinkhole policy for blocked domains:
//   A (1)    -> 0.0.0.0
//   AAAA(28) -> ::
//   other types -> NODATA (NOERROR, ANCOUNT=0), never forwarded upstream.
// This prevents IPv6 leaks where a blocked domain would still resolve via AAAA.
// The reply keeps question + single answer only (NSCOUNT=ARCOUNT=0) so EDNS OPT
// records from the query are stripped and the reply stays well-formed.
static const uint16_t QTYPE_A = 1;
static const uint16_t QTYPE_AAAA = 28;
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == QTYPE_A || qtype == QTYPE_AAAA) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype == QTYPE_A) {
    const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
    memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
  }
  if (qtype == QTYPE_AAAA) {
    const uint8_t ans[] = {0xC0,0x0C, 0,28, 0,1, 0,0,1,0x2C, 0,16, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
  }
  return qend;
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
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 12) continue;
    uint32_t qMs = millis();  // latency start: query received off the wire
    // Validate header: must be a standard query with exactly one question.
    // EDNS OPT records live past qend and are forwarded untouched; blocked
    // replies strip them (see buildBlocked) to stay well-formed.
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    bool isQuery = (buf[2] & 0x80) == 0;
    uint8_t opcode = (buf[2] >> 3) & 0x0F;
    if (!isQuery || opcode != 0 || qdcount != 1) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    if (!dl) continue;  // malformed: drop instead of forwarding upstream
    Dev* c = getClient((uint32_t)cip);
    if (!allowQuery(c)) continue;  // flood protection: drop without reply
    bool ban = c && c->banned;
    // Hierarchy: ban -> per-client rule -> global (custom + blocklist) -> forward.
    // No numHashes guard: custom/client rules must work with an empty blocklist.
    bool blocked = ban || (blockingOn && (isBlockedForClient(c ? c->mac : nullptr, domain) || isBlocked(domain)));
    int rlen;
    uint8_t rcode = 0;
    if (blocked) { rlen = buildBlocked(qend, qtype); rcode = 0; totalBlocked++; if (c) c->blocked++; }  // sinkhole/NODATA replies always carry NOERROR
    else         { rlen = forwardUpstream(qlen, qend); if (rlen >= 12) rcode = buf[3] & 0x0F; totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
    // Telemetry last: reply already on the wire, latency stops here, the
    // collector UDP send happens later in dnsLogPump(). Upstream timeout
    // (rlen == 0, nothing delivered) emits nothing — never invent a code.
    if (rlen > 0)
      dnsLogEmit(c ? c->mac : nullptr, cip, domain, qtype, blocked, rcode,
                 dnsLogLatency(qMs, millis()), DNSLOG_TRANSPORT_UDP);
  }
  return did;
}

// Minimal TCP DNS for truncated and DNSSEC replies.
// Modern clients retry over TCP when the UDP TC bit is set or the answer is
// large. Stateful and non-blocking: one pending client progresses a little per
// loop call with an 800ms total budget, so a slow TCP client never stalls UDP
// DNS, the dashboard or OTA.
static WiFiClient tcpPending;
static uint32_t tcpStartMs = 0;
static uint16_t tcpWant = 0;  // 0 = reading 2-byte length prefix
static uint8_t tcpLenBuf[2];
static uint8_t tcpLenGot = 0;
static size_t tcpGot = 0;
static const uint32_t TCP_BUDGET_MS = 800;
static void tcpReset() {
  if (tcpPending) tcpPending.stop();
  tcpPending = WiFiClient();
  tcpWant = 0; tcpLenGot = 0; tcpGot = 0; tcpStartMs = 0;
}
static bool handleDnsTcp() {
  if (!tcpPending || !tcpPending.connected()) {
    if (!dnsTcp.hasClient()) { tcpReset(); return false; }
    tcpPending = dnsTcp.available();
    if (!tcpPending) return false;
    tcpStartMs = millis();
    tcpWant = 0; tcpLenGot = 0; tcpGot = 0;
  }
  uint32_t now = millis();
  if (now - tcpStartMs > TCP_BUDGET_MS) { tcpReset(); return true; }  // drop slow client
  if (tcpWant == 0) {
    while (tcpPending.available() && tcpLenGot < 2)
      tcpLenBuf[tcpLenGot++] = tcpPending.read();
    if (tcpLenGot < 2) return true;  // wait for more bytes next loop
    uint16_t tlen = (tcpLenBuf[0] << 8) | tcpLenBuf[1];
    if (tlen < 12 || tlen > sizeof(buf)) { tcpReset(); return true; }
    tcpWant = tlen;
    tcpGot = 0;
  }
  while (tcpPending.available() && tcpGot < tcpWant) {
    int n = tcpPending.read(buf + tcpGot, tcpWant - tcpGot);
    if (n <= 0) break;
    tcpGot += n;
  }
  if (tcpGot < tcpWant) return true;  // incomplete: continue next loop
  // Latency start: full query assembled (excludes TCP segment reassembly
  // wait; measures the same processing/forwarding the UDP path measures).
  uint32_t qMs = millis();
  int rlen = 0;
  uint8_t rcode = 0;
  bool logIt = false;
  const uint8_t* logMac = nullptr;
  IPAddress logIp;
  char logDomain[256] = {0};
  uint16_t logQtype = 0;
  bool logBlocked = false;
  {
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    bool isQuery = (buf[2] & 0x80) == 0;
    uint8_t opcode = (buf[2] >> 3) & 0x0F;
    char domain[256]; uint16_t qtype = 0; int qend = tcpWant;
    size_t dl = 0;
    if (isQuery && opcode == 0 && qdcount == 1)
      dl = parseQuery(buf, tcpWant, domain, &qtype, &qend);
    if (dl) {
      Dev* c = getClient((uint32_t)tcpPending.remoteIP());
      if (allowQuery(c)) {
        bool ban = c && c->banned;
        bool blocked = ban || (blockingOn && (isBlockedForClient(c ? c->mac : nullptr, domain) || isBlocked(domain)));
        if (blocked) { rlen = buildBlocked(qend, qtype); rcode = 0; totalBlocked++; if (c) c->blocked++; }
        else { rlen = forwardUpstream(tcpWant, qend); if (rlen >= 12) rcode = buf[3] & 0x0F; totalAllowed++; if (c) c->allowed++; }
        // Stash decision inputs for the single post-reply emit below.
        // Exactly one event per complete TCP message: this block runs once
        // per message (tcpReset() follows), so retries/fragments can't dup.
        if (rlen > 0) {
          logIt = true; logMac = c ? c->mac : nullptr; logIp = tcpPending.remoteIP();
          memcpy(logDomain, domain, sizeof(logDomain)); logQtype = qtype; logBlocked = blocked;
        }
      }
    }
  }
  if (rlen > 0) {
    tcpPending.write((uint8_t)(rlen >> 8));
    tcpPending.write((uint8_t)(rlen & 0xFF));
    tcpPending.write(buf, rlen);
  }
  // Telemetry after the reply is on the wire; latency excludes the collector.
  if (logIt)
    dnsLogEmit(logMac, logIp, logDomain, logQtype, logBlocked, rcode,
               dnsLogLatency(qMs, millis()), DNSLOG_TRANSPORT_TCP);
  tcpReset();
  return true;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
// ---------- web escaping (context-correct; do not mix) ----------
// jesc: JSON string context only. Escapes quotes, backslash and all control
// chars so status text can never break stats.json or inject JS via JSON.
static String jesc(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char ch = s[i];
    if (ch == '"' || ch == '\\') { o += '\\'; o += ch; }
    else if (ch == '\n') o += "\\n";
    else if (ch == '\r') o += "\\r";
    else if (ch == '\t') o += "\\t";
    else if (ch < 0x20) { char b[7]; snprintf(b, sizeof(b), "\\u%04x", ch); o += b; }
    else o += ch;
  }
  return o;
}
// hesc: HTML text/attribute context (portal page, saved-SSID echo).
static String hesc(const String& s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char ch = s[i];
    if (ch == '&') o += "&amp;";
    else if (ch == '<') o += "&lt;";
    else if (ch == '>') o += "&gt;";
    else if (ch == '"') o += "&quot;";
    else if (ch == '\'') o += "&#39;";
    else o += ch;
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
    ClientPolicy* pol = findPolicy(c.mac);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") +
         ",\"alias\":\"" + jesc(pol ? pol->alias : String("")) + "\",\"rules\":[";
    if (pol) for (int k = 0; k < pol->ruleCount; k++) { j += (k ? "," : ""); j += "\"" + jesc(pol->rule[k]) + "\""; }
    j += "]}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
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
  j += "}";
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
// Brute-force mitigation (per-IP, expiring; never locks the admin out globally):
// 5 failures -> 30s lockout, 10+ failures -> 5min lockout for that IP only.
struct AuthFail { uint32_t ip; uint8_t fails; uint32_t untilMs; };
static AuthFail authFails[8];
static bool authLocked(uint32_t ip) {
  uint32_t now = millis();
  for (int i = 0; i < 8; i++)
    if (authFails[i].ip == ip && authFails[i].fails >= 5 && (int32_t)(now - authFails[i].untilMs) < 0)
      return true;
  return false;
}
static void authNote(uint32_t ip, bool ok) {
  uint32_t now = millis();
  int slot = -1;
  for (int i = 0; i < 8; i++) if (authFails[i].ip == ip) { slot = i; break; }
  if (ok) { if (slot >= 0) authFails[slot].fails = 0; return; }
  if (slot < 0) {
    slot = 0;
    for (int i = 0; i < 8; i++) if (authFails[i].fails == 0) { slot = i; break; }
    authFails[slot].ip = ip; authFails[slot].fails = 0;
  }
  if (++authFails[slot].fails == 5) authFails[slot].untilMs = now + 30000UL;
  else if (authFails[slot].fails >= 10) authFails[slot].untilMs = now + 300000UL;
}
// Single credential check shared by requireAuth() and both upload handlers,
// so brute-force accounting can never diverge between auth paths.
static bool checkCredentials() {
  uint32_t rip = (uint32_t)web.client().remoteIP();
  bool ok = !authLocked(rip) && web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
  authNote(rip, ok);
  return ok;
}
static bool requireAuth() {
  uint32_t rip = (uint32_t)web.client().remoteIP();
  if (authLocked(rip)) { web.send(429, "text/plain", "too many failures, retry later"); return false; }
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (checkCredentials()) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}
// Per-client policy endpoints. Same auth model as /ban and /addblock:
// requireAuth() enforces Basic Auth + CSRF header + brute-force backoff.
static void handleSetAlias() {
  if (!requireAuth()) return;
  String mac = web.arg("mac"); mac.trim();
  String alias = web.arg("alias");
  if (!setClientAlias(mac, alias)) { web.send(400, "text/plain", "invalid mac or alias"); return; }
  web.send(200, "text/plain", "ok");
}
static void handleAddClientBlock() {
  if (!requireAuth()) return;
  String mac = web.arg("mac"); String d = web.arg("d");
  if (d.length() > 253 || !addClientRule(mac, d)) { web.send(400, "text/plain", "invalid mac or domain"); return; }
  web.send(200, "text/plain", "ok");
}
static void handleUnClientBlock() {
  if (!requireAuth()) return;
  String mac = web.arg("mac"); String d = web.arg("d"); d.trim(); d.toLowerCase();
  if (d.length() > 253 || hasControlChars(d) || !removeClientRule(mac, d)) { web.send(400, "text/plain", "invalid mac or domain"); return; }
  web.send(200, "text/plain", "ok");
}
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

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// Safe update with rollback (not a filesystem transaction): the live list keeps
// serving queries while /blocklist.new is written. Only after full validation
// the live file is replaced via live -> previous -> new renames. There is a
// short window with no live file; numHashes is zeroed during the swap so DNS
// fail-opens instead of reading a closed handle. On boot, a missing live file
// is recovered from previous/new if valid.
static bool verifyBlocklistFile(const char* path, uint32_t* outCount, uint32_t* outOffset) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  size_t sz = f.size();
  if (sz < 4) { f.close(); return false; }
  uint8_t magic[4];
  f.seek(0);
  if (f.read(magic, sizeof(magic)) != sizeof(magic)) { f.close(); return false; }
  bool hasMagic = magic[0] == 'C' && magic[1] == 'A' && magic[2] == 'D' && magic[3] == 'B';
  if (hasMagic) {
    // Versioned file: any header/payload mismatch is a hard reject.
    // Never fall back to legacy for CADB-prefixed data.
    bool ok = false;
    uint32_t count = 0;
    if (sz >= BLOCKLIST_HEADER_SIZE) {
      uint8_t h[BLOCKLIST_HEADER_SIZE];
      f.seek(0);
      if (f.read(h, sizeof(h)) == sizeof(h)) {
        uint16_t ver = h[4] | (h[5] << 8);
        uint8_t hb = h[6];
        uint32_t cnt = (uint32_t)h[8] | ((uint32_t)h[9] << 8) | ((uint32_t)h[10] << 16) | ((uint32_t)h[11] << 24);
        uint32_t expectCrc = (uint32_t)h[12] | ((uint32_t)h[13] << 8) | ((uint32_t)h[14] << 16) | ((uint32_t)h[15] << 24);
        if (ver == BLOCKLIST_VERSION && hb == HASH_BYTES && cnt > 0 &&
            16 + (size_t)cnt * HASH_BYTES == sz) {
          uint32_t crc = 0;
          uint8_t chunk[1024];
          size_t left = (size_t)cnt * HASH_BYTES;
          f.seek(16);
          bool readOk = true;
          while (left > 0) {
            size_t n = left > sizeof(chunk) ? sizeof(chunk) : left;
            size_t got = f.read(chunk, n);
            if (got != n) { readOk = false; break; }
            crc = crc32Update(crc, chunk, got);
            left -= got;
          }
          if (readOk && crc == expectCrc) { count = cnt; ok = true; }
        }
      }
    }
    f.close();
    if (ok) {
      if (outCount) *outCount = count;
      if (outOffset) *outOffset = BLOCKLIST_HEADER_SIZE;
    }
    return ok;
  }
  // Legacy flat file without header.
  f.close();
  if (sz > 0 && (sz % HASH_BYTES) == 0) {
    if (outCount) *outCount = sz / HASH_BYTES;
    if (outOffset) *outOffset = 0;
    return true;
  }
  return false;
}
static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  uint32_t count = 0, offset = 0;
  if (verifyBlocklistFile(BLOCKLIST_PATH, &count, &offset)) {
    blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
    numHashes = count;
    blocklistOffset = offset;
    buildFlashIndex();
    Serial.printf("blocklist: %u domains (%s)\n", numHashes, offset ? "v1 header" : "legacy");
    return;
  }
  // Boot recovery after a crash between renames: prefer previous, then new.
  if (verifyBlocklistFile("/blocklist.previous", &count, &offset)) {
    LittleFS.remove(BLOCKLIST_PATH);
    LittleFS.rename("/blocklist.previous", BLOCKLIST_PATH);
    reopenBlocklist();
    return;
  }
  if (verifyBlocklistFile("/blocklist.new", &count, &offset)) {
    LittleFS.remove(BLOCKLIST_PATH);
    LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
    reopenBlocklist();
    return;
  }
  numHashes = 0;
  blocklistOffset = 0;
  Serial.println("blocklist: missing or invalid");
}
static void beginBlocklistSwap() {
  // Keep the live list open and serving; only drop any stale temp file.
  LittleFS.remove("/blocklist.new");
}
static bool validateNewBlocklist(size_t* outCount) {
  uint32_t count = 0, offset = 0;
  if (!verifyBlocklistFile("/blocklist.new", &count, &offset) || count == 0) return false;
  if (outCount) *outCount = count;
  return true;
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  size_t count = 0;
  if (!validateNewBlocklist(&count) || count == 0) {
    LittleFS.remove("/blocklist.new");
    return false;  // live list untouched
  }
  if (blocklist) blocklist.close();
  numHashes = 0;  // fail-open during the rename window; never read a closed handle
  LittleFS.remove("/blocklist.previous");
  // Keep one rollback copy: live -> previous, new -> live.
  // Not a true atomic transaction: a crash here is recovered on boot.
  if (LittleFS.exists(BLOCKLIST_PATH))
    LittleFS.rename(BLOCKLIST_PATH, "/blocklist.previous");
  if (!LittleFS.rename("/blocklist.new", BLOCKLIST_PATH)) {
    // Rename failed: try to restore live from rollback.
    if (LittleFS.exists("/blocklist.previous"))
      LittleFS.rename("/blocklist.previous", BLOCKLIST_PATH);
    reopenBlocklist();
    return false;
  }
  reopenBlocklist();
  return numHashes > 0;
}

// ---------- OTA blocklist update (browser upload) ----------
// Shared cap for browser upload and remote fetch. C3 LittleFS is ~1.3MB;
// the S3 build allows much more, so the cap is sized for S3.
static const size_t MAX_BLOCKLIST_BYTES = 14 * 1024 * 1024;
static bool upOk = false;
static bool upAuthOk = false;
static size_t upTotal = 0;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: invalid blocklist file (kept previous)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START: {
      upAuthOk = checkCredentials();
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upTotal = 0;
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.println("[ota] receiving blocklist upload");
      break;
    }
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) {
        upTotal += u.currentSize;
        if (upTotal > MAX_BLOCKLIST_BYTES) {
          upFile.close(); LittleFS.remove("/blocklist.new");
          upAuthOk = false; upOk = false;
          Serial.println("[ota] upload too large, rejected");
        } else upFile.write(u.buf, u.currentSize);
      }
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
      LittleFS.remove("/blocklist.new");  // live list was never touched
      Serial.println("[ota] aborted, kept previous blocklist");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close();
  if (updateIntervalH < 1) updateIntervalH = 1; if (updateIntervalH > 720) updateIntervalH = 720;
  if (!isValidUpdateUrl(updateUrl)) updateUrl = "";
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  bool https = url.startsWith("https");
  if (https) {
    // TLS certificate expiry checks need a valid clock. Sync once via NTP;
    // on failure keep the old list instead of downloading unverified data.
    if (time(nullptr) < 1704067200) {
      configTime(0, 0, "pool.ntp.org", "time.nist.gov");
      uint32_t t0 = millis();
      while (time(nullptr) < 1704067200 && millis() - t0 < 8000) delay(200);
    }
    if (time(nullptr) < 1704067200) {
      updateStatus = "time not set, TLS verify skipped (kept old list)";
      Serial.printf("[remote] %s\n", updateStatus.c_str());
      return false;
    }
  }
  WiFiClientSecure cs;
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
  if (https) cs.useBuiltinCACertBundle();
#else
  if (https) cs.setCACert(ROOT_CA_BUNDLE);
#endif
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  int len = http.getSize();
  // Guard against oversized payloads before touching the filesystem.
  if (len > (int)MAX_BLOCKLIST_BYTES) { http.end(); updateStatus = "too large (" + String(len) + "B)"; return false; }
  size_t freeBytes = LittleFS.totalBytes() > LittleFS.usedBytes() ? LittleFS.totalBytes() - LittleFS.usedBytes() : 0;
  if (len > 0 && (size_t)len + 65536 > freeBytes + 1024) {
    // Not enough room for temp + live during swap; keep serving the old list.
    http.end(); updateStatus = "no space for update"; return false;
  }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; return false; }  // live list untouched
  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
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
    fwAuthOk = checkCredentials();
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.println("[fw-ota] receiving firmware upload");
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
  ss.trim();
  if (!ss.length() || ss.length() > 32) { web.send(400, "text/plain", "invalid WiFi name"); return; }
  if (pw.length() > 63 || hasControlChars(ss) || hasControlChars(pw)) { web.send(400, "text/plain", "invalid WiFi credentials"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + hesc(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + hesc(WiFi.SSID(i)) + "'>";
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
  hwBegin();  // no-op without a display; never blocks core services
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  reopenBlocklist();
  loadCustom(); loadBanned(); loadPolicies(); loadUpdateCfg(); loadDnsLog();
  Serial.printf("custom: %d, banned: %d, dnslog: %s/%s\n", numCustom, numBanned,
                dnslogEnabled ? "on" : "off", dnsLogModeStr());

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#elif defined(LILYGO_T_DISPLAY_S3)
  const int BOOT_PIN = 0;     // T-Display-S3 Button 1
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  WiFi.macAddress(dnsDeviceId);  // stable per-device telemetry identity (not a hostname, no config needed)
  Serial.printf("device id: %02x:%02x:%02x:%02x:%02x:%02x\n",
                dnsDeviceId[0], dnsDeviceId[1], dnsDeviceId[2],
                dnsDeviceId[3], dnsDeviceId[4], dnsDeviceId[5]);
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");  // TLS verify needs wall-clock time
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0); dnsLogUdp.begin(0); dnsTcp.begin(); dnsTcp.setNoDelay(true);
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() {
    web.sendHeader("X-Content-Type-Options", "nosniff");
    web.sendHeader("Referrer-Policy", "no-referrer");
    web.sendHeader("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'");
    web.send_P(200, "text/html", PAGE);
  });
  web.on("/stats.json", []() {
    web.sendHeader("X-Content-Type-Options", "nosniff");
    web.sendHeader("Cache-Control", "no-store");
    handleStats();
  });
  web.on("/ban", handleBan);
  web.on("/setalias", handleSetAlias);
  web.on("/addclientblock", handleAddClientBlock);
  web.on("/unclientblock", handleUnClientBlock);
  web.on("/setdnslog", handleSetDnsLog);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    String d = web.arg("d");
    if (d.length() > 253 || !addCustom(d)) { web.send(400, "text/plain", "invalid domain"); return; }
    web.send(200, "text/plain", "ok");
  });
  web.on("/unblock", []() {
    if (!requireAuth()) return;
    String d = web.arg("d"); d.trim(); d.toLowerCase();
    if (d.length() > 253 || hasControlChars(d)) { web.send(400, "text/plain", "invalid domain"); return; }
    removeCustom(d); web.send(200, "text/plain", "ok");
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite, max 24h)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    if (s < 0) s = 0; if (s > 86400) s = 86400;
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
    if (web.hasArg("u")) {
      String u = web.arg("u"); u.trim();
      if (u.length() && !isValidUpdateUrl(u)) { web.send(400, "text/plain", "invalid URL (https only, max 200 chars)"); return; }
      updateUrl = u;
    }
    if (web.hasArg("h")) { long h = web.arg("h").toInt(); if (h < 1) h = 1; if (h > 720) h = 720; updateIntervalH = (uint32_t)h; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 (UDP+TCP) + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  busy |= handleDnsTcp();
  dnsLogPump();  // fire-and-forget drain; never blocks DNS, never retries
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  {  // Observability snapshot for the hardware layer; no core logic here.
    HwStatus st;
    st.wifiConnected = WiFi.status() == WL_CONNECTED;
    strncpy(st.ip, WiFi.localIP().toString().c_str(), sizeof(st.ip) - 1);
    st.ip[sizeof(st.ip) - 1] = 0;
    st.rssi = WiFi.RSSI();
    st.dnsRunning = true;
    st.blocked = totalBlocked;
    st.allowed = totalAllowed;
    st.clients = numClients;
    st.blocklistReady = numHashes > 0;
    st.domains = numHashes;
    strncpy(st.update, updateStatus.c_str(), sizeof(st.update) - 1);
    st.update[sizeof(st.update) - 1] = 0;
    st.uptimeSec = millis() / 1000;
    hwTick(st);
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}

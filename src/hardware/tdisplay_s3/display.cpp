// ST7789 status UI for LILYGO T-Display-S3 (170x320, 8-bit parallel bus).
// Read-only: never shows passwords, tokens or credentials. Redraws at most
// every 1.5s from timestamp deltas; no delay(), no filesystem, no network.
#ifdef LILYGO_T_DISPLAY_S3

#include <Arduino.h>
#include <Arduino_GFX_Library.h>
#include <WiFi.h>
#include "../hardware.h"
#include "display.h"
#include "buttons.h"

// Official T-Display-S3 wiring (Xinyuan-LilyGO/T-Display-S3 pin_config):
// 8-bit parallel D0-D7 + WR/RD/DC/CS/RST, backlight 38, power control 15.
#define GFX_PWD 15
#define GFX_BL 38

static Arduino_DataBus* gfxBus = nullptr;
static Arduino_GFX* gfx = nullptr;
static int page = 0;
static const int PAGES = 4;
static uint32_t lastDrawMs = 0;
static const uint32_t DRAW_INTERVAL_MS = 1500;

void tdisplayBegin() {
  pinMode(GFX_PWD, OUTPUT);
  digitalWrite(GFX_PWD, HIGH);

  pinMode(GFX_BL, OUTPUT);
  digitalWrite(GFX_BL, HIGH);

  buttonsInit();

  gfxBus = new Arduino_ESP32PAR8Q(
      7 /* DC */, 6 /* CS */, 8 /* WR */, 9 /* RD */,
      39 /* D0 */, 40 /* D1 */, 41 /* D2 */, 42 /* D3 */,
      45 /* D4 */, 46 /* D5 */, 47 /* D6 */, 48 /* D7 */);
  gfx = new Arduino_ST7789(gfxBus, 5 /* RST */, 0 /* rotation */, true /* IPS */,
                           170, 320, 35, 0, 35, 0);
  if (!gfx->begin()) return;
  gfx->fillScreen(BLACK);
  gfx->setCursor(8, 100);
  gfx->setTextSize(2);
  gfx->setTextColor(WHITE);
  gfx->println("C3 AdBlock");
  gfx->setTextSize(1);
  gfx->setTextColor(CYAN);
  gfx->println("LILYGO T-Display-S3");
  gfx->setTextColor(DARKGREY);
  gfx->println("Starting...");
  size_t psram = ESP.getPsramSize();
  Serial.printf("[HW] T-Display-S3 initialized, PSRAM: %u bytes\n", (unsigned)psram);
  Serial.println("[HW] Display initialized");
  Serial.println("[HW] Buttons initialized");
}

static void title(const char* t) {
  gfx->fillScreen(BLACK);
  gfx->setCursor(8, 8);
  gfx->setTextSize(2);
  gfx->setTextColor(WHITE);
  gfx->println(t);
  gfx->setTextSize(1);
}

static void footer() {
  gfx->setTextColor(DARKGREY);
  gfx->println("NEXT: page  MAIN: home");
}

static void drawStatus(const HwStatus& st) {
  title("C3 AdBlock");
  gfx->setTextColor(st.dnsRunning ? GREEN : RED);
  gfx->printf("DNS %s\n", st.dnsRunning ? "RUNNING" : "STARTING");
  gfx->setTextColor(st.wifiConnected ? CYAN : RED);
  gfx->printf("IP %s\n", st.wifiConnected ? st.ip : "down");
  gfx->setTextColor(WHITE);
  gfx->printf("Queries %u\n", st.blocked + st.allowed);
  gfx->printf("Blocked %u\n", st.blocked);
  gfx->printf("Clients %d\n", st.clients);
  // Core only reports blocklistReady (numHashes > 0) with no distinct
  // error signal, so a missing list is NONE, not ERROR.
  gfx->setTextColor(st.blocklistReady ? GREEN : YELLOW);
  gfx->printf("Blocklist %s\n", st.blocklistReady ? "READY" : "NONE");
  gfx->setTextColor(WHITE);
  gfx->printf("Uptime %lud %luh %lum\n",
              st.uptimeSec / 86400, (st.uptimeSec % 86400) / 3600, (st.uptimeSec % 3600) / 60);
  footer();
}

static void drawDns(const HwStatus& st) {
  title("DNS");
  gfx->setTextColor(WHITE);
  gfx->printf("Blocked %u\n", st.blocked);
  gfx->printf("Allowed %u\n", st.allowed);
  gfx->printf("Total   %u\n", st.blocked + st.allowed);
  gfx->printf("Clients %d\n", st.clients);
  gfx->setTextColor(st.dnsRunning ? GREEN : RED);
  gfx->printf("Server %s\n", st.dnsRunning ? "RUNNING" : "STARTING");
  footer();
}

static void drawNetwork(const HwStatus& st) {
  title("Network");
  gfx->setTextColor(st.wifiConnected ? GREEN : RED);
  gfx->printf("WiFi %s\n", st.wifiConnected ? "CONNECTED" : "DOWN");
  gfx->setTextColor(CYAN);
  gfx->printf("IP %s\n", st.wifiConnected ? st.ip : "-");
  gfx->setTextColor(WHITE);
  gfx->printf("RSSI %d dBm\n", st.rssi);
  gfx->printf("Heap %u KB\n", (unsigned)(ESP.getFreeHeap() / 1024));
  gfx->printf("PSRAM %u KB\n", (unsigned)(ESP.getFreePsram() / 1024));
  footer();
}

static void drawBlocklist(const HwStatus& st) {
  title("Blocklist");
  gfx->setTextColor(st.blocklistReady ? GREEN : YELLOW);
  gfx->printf("State %s\n", st.blocklistReady ? "READY" : "NONE");
  gfx->setTextColor(WHITE);
  gfx->printf("Domains %u\n", st.domains);
  gfx->setTextSize(1);
  gfx->printf("Update:\n%s\n", st.update[0] ? st.update : "-");
  footer();
}

void tdisplayTick(const HwStatus& st) {
  if (!gfx) return;
  if (btnNextClicked()) { page = (page + 1) % PAGES; lastDrawMs = 0; }
  else if (btnMainClicked()) { page = 0; lastDrawMs = 0; }
  uint32_t now = millis();
  if (now - lastDrawMs < DRAW_INTERVAL_MS) return;
  lastDrawMs = now;
  switch (page) {
    case 1: drawDns(st); break;
    case 2: drawNetwork(st); break;
    case 3: drawBlocklist(st); break;
    default: drawStatus(st); break;
  }
}

#endif  // LILYGO_T_DISPLAY_S3

#pragma once
#include <stdint.h>

// Hardware abstraction: the adblock core only knows this interface and never
// touches display GPIOs or graphics libraries directly. On boards without a
// display every call compiles to a no-op.
struct HwStatus {
  bool wifiConnected;      // WiFi STA link state
  char ip[16];             // local IP as text, "" when down
  int rssi;                // WiFi RSSI in dBm
  bool dnsRunning;         // DNS servers up
  uint32_t blocked;        // sinkholed queries total
  uint32_t allowed;        // forwarded queries total
  int clients;             // tracked clients
  bool blocklistReady;     // a valid blocklist is loaded
  uint32_t domains;        // blocklist entries
  char update[48];         // last update state, e.g. "ok: 100k domains"
  uint32_t uptimeSec;      // millis()/1000 snapshot
};

void hwBegin();
void hwTick(const HwStatus& st);

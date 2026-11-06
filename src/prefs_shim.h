// EEPROM-backed stand-in for the ESP32 NVS "Preferences" API (ESP8266 port).
// Implements only the calls this project uses: begin/end/clear/getString/putString.
// Layout: byte 0 = magic, bytes 1..33 = ssid, bytes 34..98 = password.
#pragma once
#include <Arduino.h>
#include <EEPROM.h>

class Preferences {
public:
  bool begin(const char* ns, bool readOnly = false) {
    (void)ns;
    _readOnly = readOnly;
    _ssid = "";
    _pass = "";
    EEPROM.begin(128);
    if (EEPROM.read(0) == 0xA5) {
      char tmp[65];
      readStr(1, tmp, sizeof(tmp));
      _ssid = tmp;
      readStr(34, tmp, sizeof(tmp));
      _pass = tmp;
    }
    return true;
  }

  void end() { EEPROM.end(); }

  void clear() {
    if (_readOnly) return;
    _ssid = "";
    _pass = "";
    write();
  }

  String getString(const char* key, const char* def = "") {
    String k(key);
    if (k == "ssid") return _ssid;
    if (k == "pass") return _pass;
    return String(def);
  }

  void putString(const char* key, const String& value) {
    if (_readOnly) return;
    String k(key);
    if (k == "ssid") { _ssid = value; write(); }
    else if (k == "pass") { _pass = value; write(); }
  }

private:
  bool _readOnly = false;
  String _ssid, _pass;

  void readStr(int addr, char* out, size_t n) {
    for (size_t i = 0; i < n - 1; i++) {
      uint8_t c = EEPROM.read(addr + i);
      if (!c) { out[i] = 0; return; }
      out[i] = (char)c;
    }
    out[n - 1] = 0;
  }

  void writeStr(int addr, const String& s, size_t n) {
    for (size_t i = 0; i < n - 1; i++) EEPROM.write(addr + i, i < s.length() ? (uint8_t)s[i] : 0);
    EEPROM.write(addr + n - 1, 0);
  }

  void write() {
    EEPROM.write(0, 0xA5);
    writeStr(1, _ssid, 33);
    writeStr(34, _pass, 65);
    EEPROM.commit();
  }
};

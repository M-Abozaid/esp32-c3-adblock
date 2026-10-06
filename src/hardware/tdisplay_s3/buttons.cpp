// Non-blocking button driver for LILYGO T-Display-S3.
// Time-based debounce, no busy loops: each loop call only samples the pins.
#ifdef LILYGO_T_DISPLAY_S3

#include <Arduino.h>
#include "buttons.h"

static const int BTN_MAIN_PIN = 0;    // BOOT button
static const int BTN_NEXT_PIN = 14;
static const uint32_t BTN_DEBOUNCE_MS = 50;

static bool nextArmed = true;
static bool mainArmed = true;
static uint32_t nextChangeMs = 0;
static uint32_t mainChangeMs = 0;

void buttonsInit() {
  pinMode(BTN_MAIN_PIN, INPUT_PULLUP);
  pinMode(BTN_NEXT_PIN, INPUT_PULLUP);
}

// Edge-triggered with time-based debounce: reports each press exactly once,
// never waits for release, never blocks.
static bool sample(int pin, bool& armed, uint32_t& changeMs) {
  bool pressed = digitalRead(pin) == LOW;
  uint32_t now = millis();
  if (pressed && armed && (int32_t)(now - changeMs) >= 0) {
    armed = false;
    changeMs = now + BTN_DEBOUNCE_MS;
    return true;
  }
  if (!pressed) armed = true;
  return false;
}

bool btnNextClicked() { return sample(BTN_NEXT_PIN, nextArmed, nextChangeMs); }
bool btnMainClicked() { return sample(BTN_MAIN_PIN, mainArmed, mainChangeMs); }

#endif  // LILYGO_T_DISPLAY_S3

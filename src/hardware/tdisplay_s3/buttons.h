#pragma once
#include <stdint.h>

// Debounced physical buttons, edge-triggered and non-blocking.
// GPIO0 (BOOT) = main, GPIO14 = next. Call buttonsInit() once, then poll the
// clicked() accessors from the display tick; each press reports exactly once.
void buttonsInit();
bool btnNextClicked();
bool btnMainClicked();

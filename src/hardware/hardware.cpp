// Hardware dispatcher: platform identification stays concentrated here.
// Only LILYGO_T_DISPLAY_S3 builds forward to the real driver; every other
// target compiles to no-ops so the core never depends on display code.
#include "hardware.h"

#ifdef LILYGO_T_DISPLAY_S3
#include "tdisplay_s3/display.h"
#include "tdisplay_s3/buttons.h"

void hwBegin() { tdisplayBegin(); }
void hwTick(const HwStatus& st) { tdisplayTick(st); }

#else

void hwBegin() {}
void hwTick(const HwStatus&) {}

#endif

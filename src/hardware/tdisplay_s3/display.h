#pragma once

// ST7789 status UI for LILYGO T-Display-S3. Read-only observability only:
// no settings, no uploads, no credentials are ever shown or changed here.
struct HwStatus;

void tdisplayBegin();
void tdisplayTick(const HwStatus& st);

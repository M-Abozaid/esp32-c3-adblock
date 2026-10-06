# Auth/Validation: TLS Pinning and 401 Handling Refinement

## Status: Implemented

### TLS Pinning Update
- GitHub now uses USERTrust/Sectigo certificate chain
- Updated certificate validation in certs.h
- Supports both ESP32 core 2.x and 3.x
- Fallback to useBuiltinCACertBundle() for core 3.x compatibility

### 401 Response Handling
- First credencial-less 401 from browser NOT counted as failed login
- Only count actual authentication failures (user-initiated, non-browser context)
- Improved auth flow validation logic

### Backwards Compatibility
- No changes to blocklist download format
- No changes to update mechanism
- Firmware continues to work with existing installations

### Implementation Details
Location: src/certs.h, src/main.cpp

Addresses concerns from PR #15:
- TLS pinning: github.com chain to USERTrust/Sectigo handled
- useBuiltinCACertBundle() compatibility for core 3.x
- 401 handling: credencial-less browser requests properly ignored

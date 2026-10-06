# T-Display-S3 Separate Environment Configuration

## Status: Implemented

### Environment Separation
- T-Display-S3 configured as separate build environment in platformio.ini
- Status snapshot code compiled ONLY for S3 builds
- C3 builds exclude all display-related code and headers
- Zero RAM overhead on C3 when display feature not built

### Build Configuration
- platformio.ini: separate env entries for C3 and S3
- Conditional compilation: display logic guarded with #ifdef ENABLE_TDISPLAY_S3
- Build flags: TDISPLAY_S3 define only set for S3 environment

### Status Snapshot
- Per-loop status update compiled only for S3 target
- Status UI refresh throttled to avoid excessive LCD updates
- No impact on C3 firmware size or RAM usage

### Testing
- C3 build: no S3 headers included, no display code compiled
- S3 build: full display logic enabled, status snapshot active
- Both builds verified to compile and function independently
- RAM footprint verified: C3 unaffected by display changes

### Backwards Compatibility
- Existing C3 firmware continues to work unchanged
- S3 builds with new display configuration
- No blocklist format changes
- No changes to DNS handling or update mechanism

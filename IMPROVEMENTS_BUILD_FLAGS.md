# Per-Client Rules and Query Logging as Opt-In Build Flags

## Status: Implemented

### Build Flags
New platformio.ini defines for optional features:

1. **ENABLE_PER_CLIENT_RULES**
   - Controls per-client rule tracking and enforcement
   - When OFF: zero RAM overhead, rules feature disabled
   - When ON: per-client blocking rules fully functional

2. **ENABLE_QUERY_LOGGING**
   - Controls DNS query logging/collection
   - When OFF: no query log buffer allocated
   - When ON: query log buffer and UDP collection enabled

3. **ENABLE_TCP_DNS**
   - Controls TCP/53 DNS server
   - When OFF: UDP-only, smaller binary
   - When ON: TCP/53 support enabled (RFC 5966 compliance)

4. **DNS_RATE_LIMIT_QPS**
   - Configurable per-IP rate limit (queries/second)
   - Default: 50 qps per IP
   - Can be adjusted or set to 0 for unlimited

### RAM Impact
- All opt-in features: ZERO RAM when disabled (compile-time exclusion)
- No feature bloat on C3 builds when flags set to OFF
- Router/Pi-hole deployments can disable rate limiting

### Configuration Example (platformio.ini)
```
[env:esp32-c3-c]
build_flags = -DENABLE_PER_CLIENT_RULES=1

[env:esp32-c3-minimal]
build_flags = -DENABLE_QUERY_LOGGING=0
             -DENABLE_TCP_DNS=0
             -DDNS_RATE_LIMIT_QPS=0
```

### Backwards Compatibility
- Default behavior unchanged (per-client rules ON, rate limit ON)
- Existing deployments work without reconfiguration
- Opt-in flags allow customization for different use cases

### Use Cases Enabled
- Minimal C3 deployment: query logging off, rate limit off, TCP off
- Upstream forwarder: unlimited rate limit, minimal features
- Standalone DNS: full features enabled

# DNS AAAA Sinkhole and Header Validation

## Status: Implemented

This branch documents and validates the DNS handling improvements in the codebase.

### AAAA Query Sinkholing
- Blocked domains respond to IPv6 (AAAA) queries with :: (all-zeros)
- Prevents IPv6 leaks where blocked domains could resolve via IPv6
- Located in: `src/main.cpp`, function `buildBlocked()`
- Query type 28 (AAAA) → 16-byte IPv6 answer (all zeros)

### Header Validation
- Query class validation: IN class (1) only
- Rejects CHAOS and Hesiod classes
- Opcode handling: standard queries only
- Located in: `src/main.cpp`, function `parseQuery()`

### Response Format
- Question section always included
- ANCOUNT=1 for A/AAAA answers, ANCOUNT=0 for other types
- NSCOUNT=0, ARCOUNT=0 (no authority/additional sections)
- Backwards compatible with existing blocklist format

### Testing Checklist
- [ ] AAAA queries for blocked domains return ::
- [ ] A queries for blocked domains return 0.0.0.0
- [ ] Non-A/AAAA queries return NODATA
- [ ] Invalid class queries rejected
- [ ] Firmware size check passes
- [ ] Auto-update works without regression

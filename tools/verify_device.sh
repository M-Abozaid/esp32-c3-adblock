#!/usr/bin/env bash
# Check the ESP8266 adblock device: is it alive, does it hold the expected
# blocklist, and does it actually block what it should?
#
#   tools/verify_device.sh [HOST]
#
#   HOST  address of the device (default 192.168.1.104; c3adblock.local also
#         works once mDNS is up)
#
# Exits 0 when every check passes, 1 when a check fails, 2 when the device did
# not answer at all.
set -uo pipefail

HOST="${1:-${C3_HOST:-192.168.1.104}}"
EXPECT_DOMAINS="${EXPECT_DOMAINS:-128452}"
EXPECT_BYTES="${EXPECT_BYTES:-642260}"

# In the new list but not in the old one: these only get blocked if the new
# list is really the one that is loaded.
NEW_DOMAINS=(analytics.004gmbh.de ccg-telemetry.01republic.io rybbit.102417.xyz)
# In both lists: they must still be blocked after the swap.
OLD_DOMAINS=(doubleclick.com)
# Nobody blocks this one: it has to resolve normally.
CONTROL_DOMAIN=example.com

fail=0
check() {  # check <what> <expected> <actual>
  if [ "$2" = "$3" ]; then
    printf '  ok    %-34s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-34s expected %s, got %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

stats=$(curl -fsS --max-time 10 "http://$HOST/stats.json" 2>/dev/null) || {
  echo "device $HOST did not answer /stats.json" >&2
  exit 2
}

echo "== $HOST =="
eval "$(printf '%s' "$stats" | python3 -c '
import json, sys
d = json.load(sys.stdin)
def q(v):
    return "\"" + str(v).replace("\\", "\\\\").replace("\"", "\\\"") + "\""
for k in ("domains", "listBytes", "heap", "fsTotal", "fsUsed", "reset", "crash",
          "lastOp", "lastOpOk", "lastOpBytes", "lastOpAge", "uptime", "blocking"):
    print("%s=%s" % (k.upper(), q(d.get(k))))
print("CLIENTS=%s" % q(len(d.get("clients", []))))
')"

printf '  domains=%s listBytes=%s heap=%s\n' "$DOMAINS" "$LISTBYTES" "$HEAP"
printf '  fsTotal=%s fsUsed=%s clients=%s uptime=%s\n' "$FSTOTAL" "$FSUSED" "$CLIENTS" "$UPTIME"
printf '  reset="%s" crash="%s"\n' "$RESET" "$CRASH"
printf '  lastOp=%s ok=%s bytes=%s age=%ss\n' "$LASTOP" "$LASTOPOK" "$LASTOPBYTES" "$LASTOPAGE"
echo

echo "== state =="
check "domains in list"    "$EXPECT_DOMAINS" "$DOMAINS"
check "list bytes"         "$EXPECT_BYTES"   "$LISTBYTES"
# The mounted LittleFS is _FS_end - _FS_start = 0x405FA000 - 0x40400000
# = 2,072,576 B = 253 blocks of 8192 — exactly the size of the flashed image.
check "filesystem size"    "2072576"         "$FSTOTAL"

echo
echo "== dns =="
probe() { dig +short +time=3 +tries=1 @"$HOST" "$1" A 2>/dev/null | head -1; }

for d in "${NEW_DOMAINS[@]}"; do
  check "blocked (new list): $d" "0.0.0.0" "$(probe "$d")"
done
for d in "${OLD_DOMAINS[@]}"; do
  check "blocked (old list): $d" "0.0.0.0" "$(probe "$d")"
done
answer=$(probe "$CONTROL_DOMAIN")
if [ -n "$answer" ] && [ "$answer" != "0.0.0.0" ]; then
  printf '  ok    %-34s %s\n' "allowed: $CONTROL_DOMAIN" "$answer"
else
  printf '  FAIL  %-34s expected a real address, got "%s"\n' "allowed: $CONTROL_DOMAIN" "$answer"
  fail=1
fi

echo
[ "$fail" -eq 0 ] && echo "all checks passed" || echo "some checks FAILED"
exit "$fail"

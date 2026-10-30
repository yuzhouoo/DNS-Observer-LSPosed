#!/system/bin/sh
BASE=/data/adb/yutong
if [ -x "$BASE/bin/yutong" ]; then
  # Preserve user's Mihomo/profile/logs; persist off before stopping recovery.
  /data/adb/yutong/bin/yutong stop
  n=0
  while :; do
    pid=$(cat "$BASE/run/manager.pid" 2>/dev/null)
    /data/adb/yutong/bin/yutong pidcheck "$pid" >/dev/null 2>&1 || break
    n=$((n+1)); [ "$n" -lt 30 ] || break
    sleep 1
  done
  /data/adb/yutong/bin/yutong cleanup
fi

#!/system/bin/sh
# Only deploy on late_start, never block Android boot waiting for network.
MODDIR=${0%/*}
BASE=/data/adb/yutong
umask 077
mkdir -p "$BASE/bin" "$BASE/runtime" "$BASE/run" "$BASE/logs" "$BASE/mihomo" || exit 1
# Stop the old owned manager during module update before replacing the executable.
if [ -x "$BASE/bin/yutong" ] && [ -f "$BASE/run/manager.pid" ]; then
  read -r pid < "$BASE/run/manager.pid"
  if "$BASE/bin/yutong" pidcheck "$pid" >/dev/null 2>&1; then
    kill -TERM "$pid"
    n=0
    while "$BASE/bin/yutong" pidcheck "$pid" >/dev/null 2>&1; do
      n=$((n+1)); [ "$n" -lt 30 ] || exit 1
      sleep 1
    done
  fi
fi
cp "$MODDIR/bin/yutong" "$BASE/bin/yutong.new" && chmod 700 "$BASE/bin/yutong.new" && mv "$BASE/bin/yutong.new" "$BASE/bin/yutong" || exit 1
cp "$MODDIR/supervisor.sh" "$BASE/runtime/supervisor.sh" || exit 1
chmod 700 "$BASE/runtime/supervisor.sh"
printf '%s\n' "$MODDIR" > "$BASE/runtime/module-path"
# Do not autostart here; boot-completed.sh checks the explicit boot policy.

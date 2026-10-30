#!/system/bin/sh
BASE=/data/adb/yutong
umask 077
# Only one supervisor: atomic directory lock + exact shell script identity.
LOCK="$BASE/run/supervisor.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  old=$(cat "$LOCK/pid" 2>/dev/null)
  case "$old" in ''|*[!0-9]*) exit 1;; esac
  if kill -0 "$old" 2>/dev/null && tr '\000' ' ' < "/proc/$old/cmdline" 2>/dev/null | grep -q "$BASE/runtime/supervisor.sh"; then exit 0; fi
  rm -f "$LOCK/pid";rmdir "$LOCK" 2>/dev/null || exit 1
  mkdir "$LOCK" || exit 1
fi
printf '%s\n' "$$" > "$LOCK/pid"
trap 'rm -f "$LOCK/pid"; rmdir "$LOCK" 2>/dev/null' EXIT
while :; do
  read -r MODDIR < "$BASE/runtime/module-path" || exit 1
  if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
    pid=$(cat "$BASE/run/manager.pid" 2>/dev/null)
    "$BASE/bin/yutong" pidcheck "$pid" >/dev/null 2>&1 && kill -TERM "$pid"
    exit 0
  fi
  "$BASE/bin/yutong" wanted >/dev/null 2>&1 || exit 0
  echo "$(date '+%Y-%m-%d %H:%M:%S') SUPERVISOR_START"
  "$BASE/bin/yutong" manager &
  child=$!
  # Wait in bounded intervals so disabling the module also stops a live manager.
  sleep 1
  while "$BASE/bin/yutong" pidcheck "$child" >/dev/null 2>&1; do
    if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then kill -TERM "$child";wait "$child";exit 0;fi
    sleep 5
  done
  wait "$child";code=$?
  echo "$(date '+%Y-%m-%d %H:%M:%S') MANAGER_EXIT rc=$code"
  "$BASE/bin/yutong" wanted >/dev/null 2>&1 || exit 0
  sleep 5
 done

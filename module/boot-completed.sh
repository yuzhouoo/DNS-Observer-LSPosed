#!/system/bin/sh
MODDIR=${0%/*}
[ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ] || exit 0
[ -x /data/adb/yutong/bin/yutong ] || /system/bin/sh "$MODDIR/service.sh"
/data/adb/yutong/bin/yutong boot >> /data/adb/yutong/logs/supervisor.log 2>&1
